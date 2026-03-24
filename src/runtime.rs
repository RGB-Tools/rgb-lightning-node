use std::sync::LazyLock;

static DB_RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .thread_name("db-runtime")
        .enable_all()
        .build()
        .expect("Failed to create database tokio runtime")
});

pub(crate) fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::scope(|s| {
            s.spawn(|| DB_RUNTIME.block_on(future))
                .join()
                .expect("DB thread panicked")
        })
    } else {
        DB_RUNTIME.block_on(future)
    }
}
