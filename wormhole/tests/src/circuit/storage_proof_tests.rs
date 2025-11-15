use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use std::panic;
use wormhole_circuit::{
    storage_proof::{leaf::LeafInputs, ProcessedStorageProof, StorageProof, StorageProofTargets},
    substrate_account::SubstrateAccount,
};
use zk_circuits_common::{
    circuit::{CircuitFragment, C, D, F},
    utils::u64_to_felts,
};

use test_helpers::storage_proof::default_root_hash;
use test_helpers::TestInputs;

#[cfg(test)]
fn run_test(storage_proof: &StorageProof) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let (mut builder, mut pw) = crate::circuit_helpers::setup_test_builder_and_witness(false);
    let targets = StorageProofTargets::new(&mut builder);
    StorageProof::circuit(&targets, &mut builder);

    storage_proof.fill_targets(&mut pw, targets).unwrap();
    crate::circuit_helpers::build_and_prove_test(builder, pw)
}

#[test]
fn build_and_verify_proof() {
    let storage_proof = StorageProof::test_inputs_0();
    run_test(&storage_proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_root_hash_fails() {
    let mut proof = StorageProof::test_inputs_0();
    proof.root_hash = [0u8; 32];
    run_test(&proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn tampered_proof_fails() {
    let mut tampered_proof = ProcessedStorageProof::test_inputs_0();

    // Flip the first byte in the first node hash. Divide by two to get the byte index.
    let hash_index = tampered_proof.indices[0] / 2;
    tampered_proof.proof[0][hash_index] ^= 0xFF;
    let proof = StorageProof::new(
        &tampered_proof,
        default_root_hash(),
        LeafInputs::test_inputs_0(),
    );

    run_test(&proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_nonce() {
    let proof = ProcessedStorageProof::test_inputs_0();
    let mut leaf_inputs = LeafInputs::test_inputs_0();

    // Alter the nonce.
    leaf_inputs.transfer_count = u64_to_felts(5);

    let proof = StorageProof::new(&proof, default_root_hash(), leaf_inputs);

    run_test(&proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_exit_address() {
    let proof = ProcessedStorageProof::test_inputs_0();
    let mut leaf_inputs = LeafInputs::test_inputs_0();

    // Alter the to account.
    leaf_inputs.to_account = SubstrateAccount::new(&[0; 32]).unwrap();

    let proof = StorageProof::new(&proof, default_root_hash(), leaf_inputs);

    run_test(&proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_funding_amount() {
    let proof = ProcessedStorageProof::test_inputs_0();
    let mut leaf_inputs = LeafInputs::test_inputs_0();

    // Alter the funding amount.
    leaf_inputs.funding_amount = [
        F::from_canonical_u64(1000),
        F::from_canonical_u64(0),
        F::from_canonical_u64(0),
        F::from_canonical_u64(0),
    ];

    let proof = StorageProof::new(&proof, default_root_hash(), leaf_inputs);

    run_test(&proof).unwrap();
}

#[ignore = "performance"]
#[test]
fn fuzz_tampered_proof() {
    const FUZZ_ITERATIONS: usize = 1000;

    // Number of fuzzing iterations
    let mut panic_count = 0;

    for i in 0..FUZZ_ITERATIONS {
        // Clone the original storage proof
        let mut tampered_proof = ProcessedStorageProof::test_inputs_0();

        // Randomly select a node in the proof to tamper
        let node_index = rand::random_range(0..tampered_proof.proof.len());

        // Randomly select a byte to flip
        let byte_index = rand::random_range(0..tampered_proof.proof[node_index].len());

        // Flip random bits in the selected byte (e.g., XOR with a random value)
        tampered_proof.proof[node_index][byte_index] ^= rand::random_range(1..=255);

        // Create the proof and inputs
        let proof = StorageProof::new(
            &tampered_proof,
            default_root_hash(),
            LeafInputs::test_inputs_0(),
        );

        // Catch panic from run_test
        let result = panic::catch_unwind(|| {
            run_test(&proof).unwrap();
        });

        if result.is_err() {
            panic_count += 1;
        } else {
            // Optionally log cases where tampering didn't cause a panic
            println!("Iteration {i}: No panic occurred for tampered proof");
        }
    }

    assert_eq!(
        panic_count, FUZZ_ITERATIONS,
        "Only {panic_count} out of {FUZZ_ITERATIONS} iterations panicked",
    );
}

/// Test with actual data from debug_inputs.json
#[test]
fn real_proof_from_debug_inputs() {
    use zk_circuits_common::utils::{u64_to_felts, u128_to_felts, BytesDigest};

    // Data from debug_inputs.json
    let proof_hex = vec![
        "0000000000000020041000000000000020000000000000000177a4c670a61f4a160bbb6032818534577ea9ea085ca26ff57faaa7f590d2622000000000000000f80b484f4e0bc32564ebb2702d967d6a704461d35ae3385800fee471e203253f",
        "000000000000002048200000000000002000000000000000c73c957ca5a880d6fcc72431e597628970c63671b6bab808338b2d91cc38aedb20000000000000007a9dfa4c81b5063e28b6326dce443a0c8ba5c22f8c3ccdf4a68d93da51af19a3200000000000000027099c705ecb1c2f6c331cc4ed8ffb06c9bb41e8f57ee7097a085dad1a6ac9d3",
        "0000000000000020840000000000000020000000000000005617a8f830db8ff3d23e78c7b814b7dc36954a8f9d2ccbad7e00cafa1d82e4a0200000000000000052b3968db6181c317beaae40d8f2e63ab48803ce08c874849cbaf72e38ca0ddc",
        "0000000000000020ffb50000000000002000000000000000682dca1fecf9efaf794f65ca03a05d39bd5083913edb84bc5ac9e0e41f63d52420000000000000005bd9213525c467ba820af387f72ec42f1be3e70f81eadf3d6605ab8beba456452000000000000000366120f4cd66e1b274636cceddfc9de014589d280e7fab72443f1e47f9b3dce720000000000000001c292441747615e51a69322bbc5c83985130b3fabce1d1032c26e54ea62005642000000000000000efea993acdfdb9b332ba50094a643f961238aa6c895548ec010358aa58b003412000000000000000bdf77b65b3f23f157a6e6135ad77d4b92cece4b354b508c161bfc72ca2b32dc72000000000000000de7081164ffdd0c7de3830c217022bea42c13bca14ea9733dbc889aa5775325820000000000000009fc94159302575928fe48bf8302f60725e7180241f52279c4a33e4364ade5b9820000000000000007e7307817111d36b192832a09865dc7be7c354846314b19f524d5f202f59cff420000000000000008f755451edf9ade282cc47cb1a4eec878ca62e15d10076c705f2b77b1f5846d020000000000000007a1bf969e5e12e19c2e8c157b69b3a0dcf3878a688cff7cb7303eaee7d45b9162000000000000000aaa6b2fc3f3d43f20e0ab4666a2c59c4c4f17b7fea210a27a06f7bef7b8e4c202000000000000000cb9686eb8261ff9b8fd666ee35cfd86e0e84b83fc27e87799efbd3c7e74db3f9",
        "0000000000000020ffff0000000000002000000000000000181168032d26d984604b6aae7d5731f7c5d869bfdef6c44c801410de38908e9720000000000000001c28851f9b6e38d7a93d431f4ae6911ed83154c50b2c2aac3ea81f5b625137282000000000000000834127b63e95d109279f9120006f8776063b747e2d0872adaf1d5f3670e09a492000000000000000246cdc6b30dc50709a13b19e191f4eef52403ab27bb8498f5c2fa41541878f2d20000000000000002ef06b20cb07fba78d777e844a3031ab474d6f3b3135ee361d67111e7397b8f12000000000000000f1f9aa4778f9bc21b51346d6d712b8c966ab0f60509e3e0b0b5a9c70faa329f02000000000000000d0190100aec419edc8fb8a92a46f51748992ee8e875c9108b9634f51c847b5792000000000000000f9065f7d8d603cc15bb3e824a78360513976d8248b8f8d989b7f325c12a5949d20000000000000001086b8aa002a3db2ab63d4b509efdd8998fb7007aa3aca36e4aa7d5352e16127200000000000000036b561807f2a4c8cec6d5aaa50227209e814427e80ad507e4664b2fec689c6532000000000000000bcc3521c99cff6e127b2b21dc38cbbfeb2f1b0eb5e72c7fffb96ffb71148821a20000000000000003fa3a34691acdf11b71f10c9cd62215352cd6f27b2b4cac8e4724a15a08c2f282000000000000000af0dc2b3d443a9ac415e2dde5d342d85428532651a30c96cbc5f085da59ead4520000000000000006101577c7e97c67f9c6735abe32f8f7362741a3cb572a58a0556541f97a62f002000000000000000e810734b1cb48829b8ee47ba1ee0558e1b0eb1372fea9268c075128bcbac93062000000000000000c64eb8036a7853a49f2b64ec16289e4ef069cfbb68808602a401d0a13b2f6614",
        "0000000000000020ffff00000000000020000000000000006307c924c8877ad64d4d76b485f9323f94e66782db6572865e27e15c0a5ff44920000000000000007506bd11a19b5324b497b61999fb4c078b6c2e1effeda72d97919a21b955648d20000000000000008224dc67a5ad293bb8ba79331683dae6a272aa2fe86cb72465d122e917f22a422000000000000000a1cb0318727a43565e4f3a5a09da7f15a2c8fa9e069251d85cc8e9c4a7bd95c1200000000000000032e6087a906cdf34882be59e4f9f6d814c83cb26b10633fb6b50c3c2ec5774a3200000000000000064f8280c7820e5a5a94b9c9e00573e9effb0003e2e22a686fbc55fc9df4c37572000000000000000cb7611ddccb4316f37089b15a6328dbb95d126b86a5651da3bf8a0cad5c4394420000000000000008dcbff651d6d262df8c47fd3f7b7920566df4d4b17988b1d21651f955f7f643a200000000000000097cd6b9a855479f39ff2b12822352443a4bb557ad1d2be53580de9bf411a304e20000000000000004feb369156b48f7176097a58f5acc4e0f07af1a7b739ed916855ee8464c090362000000000000000caab9a4d254cec30ba8cc72a68425a411bbca1c76d3275cebd0c5c205b7065002000000000000000500ab52acc1c05a73170011f482f75b373ee0c4137028971a80db03c600b89502000000000000000900150e7d67e0e4224af4ffc6cb398e92f8e7f63784aca9d59cfd77c44b32656200000000000000060854793b5cdf65fa2cc7a0fe21edb1eb828f7784126534b88ad524c7780ac3020000000000000000644d4380301d8c561c2743a78dec0e2a350d17b920132019b64babafe1ea0d02000000000000000c061d7e226c73c137bb60ff816727125a38ab6c8fe99ec62163bb227cd088829",
        "0000000000000020ffff00000000000020000000000000006cbf24160f76602f92a742c6732fb2845ccc019f7bfc06d597584c7afa413139200000000000000052410b198ba226c7d5401c9a53a53abebd42c73d30296f3330169a7314264b432000000000000000995b54647a325bd6f61a597148941e955849ff68cab1c127d343cba1d6f3d755200000000000000082ef3284a463569a20ff5c421cac235a25d42efac3029d588a2d6bb6be99387020000000000000009ba0ec116463123737e5aada535a69acd7126f78406ed39903ce5bac06299f1420000000000000000b629cdf3d9c205472bc501a0e1185cd47023b62ee86a8ed73c82c29d64094a820000000000000007ead6c4ac30435702c0bc47b097b061989454100c507162ac019ab3b36664755200000000000000040c9a46bdf2ab6e5a255d5dd7cc02bff36de01215f08d9a8240d6f436a6c8b222000000000000000eb79232716a080f3cbaf2cac3223018c67e0e11f27068447da0bb31e80e2bde020000000000000009b9455c5164076b7743acf2c61811ca6e6451bc22e08282c3f22b5cbf804c3802000000000000000c1eba10486510708a81dd1eb9002b7e7c206986dbedad33cb3293290d330c8d82000000000000000d9408e80dbcd146834a5c69268eee9092aaed534d59f3eda2076d865eb64867720000000000000009ef792adbbca44f820c15689504d275f0fa222c00f3606eb84c7853aaf4a69652000000000000000db19284988ae50ce3231a163be7028dc6b71abab5ba402a6453a0603a72235a52000000000000000c62ab9b6b4dd6b59d9e6fc602b3e12d0cfe4092af0932cc5d0e96cd6b08c9f982000000000000000db585b22c0c0a048e2f766c9b7296510b46102317536cf121770f3071e3d11b0",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f0032800000000000002000000000000000cbe95bf2fb1d52fd9ae39893b24504464aedd751624449a414bb7f360a9cf2c720000000000000008466002e4b50a1f5e95a8959f2455eb754552705c1f6f62e3f03c6899b0d323c200000000000000089c6b4df29c30ed7eced51590862c3c0a91feae86cc4db6b0a742b555bb95d842000000000000000d37b6f50096495627e38c3e13b8e3a03d32e9e7286b166e6be3ffb64f79e7de8",
        "1e00000000000020857e7ea49e785c4e3e1f77a710cfc200ffff00000000000020000000000000005fa83bde67ba5c77d06d6e0b7c0a675349fb6511136534b032f63c614abd1c7d2000000000000000316e0d9f29322489f8ad72e0b6c8e0b99febe2ecce1439fc08804540ad38cb852000000000000000b9e04cc168d09b376a57bc68d86d4e5ffe799ded57645c481cc02b5ca63fb55820000000000000005ff6917cb78177ce5a31260148c3f360f24e4316de2e6c72690154814f1dc6b6200000000000000032a872ecb639a6367c10e857a8a15995d2d3914c956580900c431e24c49f307220000000000000001e49013f5e366c08052a20560993ec950fb7a5a1ba306c189f95fb34f0a7259720000000000000006ab191e3c23737e3711e2b0c9551244389e4bfcd1c3c7bb569bd605207e28ed82000000000000000e680611916827529cb638f6194cae3a84bbd91f1721b06365d0cbba80f3cbf4720000000000000007b8488dfcf7213f50446ad64693aa69d678a00b2892cef129b9a806604a998692000000000000000240a69dcaa7056a057806c6c16d678ab3e071ba459670d191f515f756ef9bcf0200000000000000023def724714b18c925879e4fd4836fbd05cae1f1b5e2ef6bf10a948889124bf42000000000000000b521073038263c69ef672f1173ac55081f62ab753f338646f4a1452cb2a6fa92200000000000000036bfcdf009e050fc7e00a533ee62052c0fb7f4c478ceceae59f925dc979e7bad2000000000000000e95f1543f95723d04d69fc6b13dd222c69dbb7ad08cb79c6f9389ad611bb6be8200000000000000033ada0f2b2e03987f35fd966c2eb0ba4681ef5d55499daebecd7ee02acb7827f200000000000000078267d6aa9aee6ee9e32963fd84a087154369edc387777ee90caa6ef10bd8232",
    ];

    let state_root_hex = "9928a1716520a707736ecbedd2832ef869c6c5443cd76f4e3c6a371e158312fa";
    let funding_account_hex = "a9d9b94bf5f32e3c678547d734ed8217c889d814d0d51880fb263ac65035b9ae";
    let to_account_hex = "b5a02bada8b84e10adbaf15cd8c50b94ae18bf39c76fff7afccf24b7cf596f56"; // unspendable_account from debug_inputs
    let funding_amount: u128 = 1000000000001;
    let transfer_count: u64 = 353396;

    // Convert hex strings to bytes
    let proof_bytes: Vec<Vec<u8>> = proof_hex
        .iter()
        .map(|hex| hex::decode(hex).expect("valid hex"))
        .collect();

    let state_root: [u8; 32] = hex::decode(state_root_hex)
        .expect("valid hex")
        .try_into()
        .expect("32 bytes");

    let funding_account: [u8; 32] = hex::decode(funding_account_hex)
        .expect("valid hex")
        .try_into()
        .expect("32 bytes");

    let to_account: [u8; 32] = hex::decode(to_account_hex)
        .expect("valid hex")
        .try_into()
        .expect("32 bytes");

    // Create LeafInputs
    let leaf_inputs = LeafInputs {
        transfer_count: u64_to_felts(transfer_count),
        funding_account: SubstrateAccount::new(&funding_account).unwrap(),
        to_account: SubstrateAccount::new(&to_account).unwrap(),
        funding_amount: u128_to_felts(funding_amount),
    };

    // For now, create a simple proof with dummy indices
    // We need to call prepare_proof_for_circuit to get the correct ordering
    // But for this test, let's use the raw proof as-is with indices calculated
    let indices = vec![0, 0, 0, 0, 0, 0, 0, 0, 0]; // placeholder indices

    let processed_proof = ProcessedStorageProof::new(proof_bytes, indices)
        .expect("valid processed proof");

    let storage_proof = StorageProof::new(&processed_proof, state_root, leaf_inputs);

    // Run the test - this should reveal what's wrong
    run_test(&storage_proof).expect("proof should verify");
}
