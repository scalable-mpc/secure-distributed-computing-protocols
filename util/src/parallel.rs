//! The bridge between the tokio runtime and the rayon thread pool.
//!
//! # Why this exists
//!
//! A tokio worker thread is shared by every task on the runtime. In this
//! repository that means every protocol instance a node is running: a single
//! `acs` run has `ctrbc`, `asks` and `ra` contexts multiplexed onto the same
//! handful of workers. A task keeps its worker only until its next `await`,
//! at which point the worker moves on to somebody else's work.
//!
//! Calling `par_iter()` (or any other rayon operation) directly from a task
//! breaks that contract. When a thread that is *not* a rayon worker enters the
//! pool, rayon parks it on a latch until the job completes — it does not
//! participate in the computation, it simply sleeps. The tokio worker is gone
//! for the whole duration, and so is every other task that was sharing it.
//! Enough concurrent calls and the runtime has no thread left to read sockets
//! with, which presents as a liveness stall rather than as slowness.
//!
//! [`compute`] fixes the direction of the wait: the job is handed to rayon and
//! the caller waits on a channel, which is a real `await`. The tokio worker is
//! released and runs other tasks while the pool does the arithmetic.
//!
//! # Not `spawn_blocking`
//!
//! `tokio::task::spawn_blocking` looks like it solves the same problem and does
//! not. It moves the work onto tokio's *blocking* pool, which grows on demand
//! up to 512 threads — so CPU-bound jobs submitted that way oversubscribe the
//! machine instead of queueing behind a fixed set of workers. Rayon's pool is
//! sized to the hardware and is the right place for arithmetic.
//!
//! # Usage
//!
//! Library crates should expose CPU-heavy work as ordinary synchronous
//! functions and keep their `par_iter` calls inside them. An `async` wrapper
//! then makes that work safe to call from a task:
//!
//! ```ignore
//! pub fn interpolate_blocking(points: Vec<Point>) -> Poly {
//!     points.into_par_iter().map(..).collect()   // fine: runs on rayon
//! }
//!
//! pub async fn interpolate(points: Vec<Point>) -> Poly {
//!     util::parallel::compute(move || interpolate_blocking(points)).await
//! }
//! ```
//!
//! Nesting is not a problem: `compute` puts the closure on a rayon worker, so
//! `par_iter` inside it is ordinary nested rayon parallelism and creates no
//! additional threads.

use std::panic::{self, AssertUnwindSafe};

use tokio::sync::oneshot;

/// Runs `f` on the global rayon pool and awaits its result without blocking
/// the calling tokio worker.
///
/// # Cancellation
///
/// Dropping the returned future — which `tokio::select!` does routinely to the
/// losing branches — stops the *waiting*, not the work. `f` runs to completion
/// on its rayon worker and its result is discarded. Nothing is left in an
/// inconsistent state by that, but the CPU time is still spent, so do not rely
/// on a timeout to shed load. Bound the number of jobs you submit instead.
///
/// # Panics
///
/// A panic inside `f` is caught and re-raised in the calling task, so it
/// unwinds the one task that asked for the work rather than the process. This
/// is deliberate: rayon's default panic handler aborts the process outright,
/// which for a node running many cascaded protocols would turn one bad share
/// into a total outage.
pub async fn compute<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = oneshot::channel();

    rayon::spawn(move || {
        // `AssertUnwindSafe` is sound here for the same reason it is in
        // tokio's own blocking pool: `f` owns everything it touches (it is
        // `FnOnce + Send + 'static`), and on a panic we hand the payload back
        // to the caller and drop the closure rather than observing whatever
        // partial state it built.
        let result = panic::catch_unwind(AssertUnwindSafe(f));
        // The receiver is gone if the caller's future was dropped. That is a
        // normal cancellation, not an error.
        let _ = tx.send(result);
    });

    match rx.await {
        Ok(Ok(value)) => value,
        Ok(Err(payload)) => panic::resume_unwind(payload),
        // The rayon worker dropped the sender without sending. `catch_unwind`
        // above makes this unreachable in practice; treat it as a bug rather
        // than silently inventing a value.
        Err(_) => panic!("rayon worker dropped the job without returning a result"),
    }
}

#[cfg(test)]
mod tests {
    use super::compute;
    use rayon::prelude::*;

    #[tokio::test]
    async fn returns_the_value() {
        let sum = compute(|| (1u64..=1000).sum::<u64>()).await;
        assert_eq!(sum, 500_500);
    }

    #[tokio::test]
    async fn nested_par_iter_is_fine() {
        // The closure lands on a rayon worker, so rayon inside it is ordinary
        // nested parallelism rather than an outside thread parking on a latch.
        let v: Vec<u64> = (0..10_000).collect();
        let sum = compute(move || v.par_iter().map(|x| x * 2).sum::<u64>()).await;
        assert_eq!(sum, 99_990_000);
    }

    #[tokio::test]
    async fn survives_concurrent_callers() {
        // The shape that matters: many tasks submitting work at once, none of
        // them holding a worker while they wait.
        let jobs = (0..64u64).map(|i| tokio::spawn(compute(move || i * i)));
        let results = futures::future::join_all(jobs).await;
        for (i, r) in results.into_iter().enumerate() {
            assert_eq!(r.unwrap(), (i as u64) * (i as u64));
        }
    }

    #[tokio::test]
    async fn panic_unwinds_the_caller_not_the_process() {
        // Rayon's default panic handler aborts the process. If `catch_unwind`
        // in `compute` ever goes away this test does not fail, it takes the
        // whole test binary down with it -- which is the point.
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(compute(|| panic!("boom")))
        }));
        assert!(caught.is_err(), "panic should have reached the caller");

        // ...and the pool is still usable afterwards.
        assert_eq!(compute(|| 7u8).await, 7);
    }

    #[tokio::test]
    async fn dropping_the_future_does_not_break_the_pool() {
        let fut = compute(|| (1u64..=100).sum::<u64>());
        drop(fut);
        assert_eq!(compute(|| 1u8 + 1).await, 2);
    }
}
