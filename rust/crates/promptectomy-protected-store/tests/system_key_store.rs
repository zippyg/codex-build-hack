use promptectomy_protected_store::{
    BackendReadiness, KeyLocator, SystemKeyStore, WrappingKeyStore, new_installation_id, new_key_id,
};

struct KeyCleanup {
    store: SystemKeyStore,
    locator: KeyLocator,
}

impl Drop for KeyCleanup {
    fn drop(&mut self) {
        let _ = self.store.delete(&self.locator);
    }
}

#[test]
#[ignore = "mutates the current user's native credential store"]
fn native_key_store_round_trip_leaves_no_test_key() {
    let store = SystemKeyStore;
    let installation_id = new_installation_id().expect("installation ID");
    let key_id = new_key_id().expect("key ID");
    let locator = KeyLocator::new(&installation_id, &key_id).expect("opaque locator");
    let cleanup = KeyCleanup {
        store,
        locator: locator.clone(),
    };
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).expect("system randomness");

    assert_eq!(store.readiness(&locator), Ok(BackendReadiness::KeyMissing));
    store.store(&locator, &key).expect("store wrapping key");
    assert_eq!(store.readiness(&locator), Ok(BackendReadiness::Ready));
    assert_eq!(
        store.load(&locator).expect("load wrapping key").as_ref(),
        &key
    );
    store.delete(&locator).expect("delete wrapping key");
    assert_eq!(store.readiness(&locator), Ok(BackendReadiness::KeyMissing));

    drop(cleanup);
}
