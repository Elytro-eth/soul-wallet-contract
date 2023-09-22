pragma solidity ^0.8.17;

import {TestBase} from "forge-std/Base.sol";

contract MockKeyStoreData is TestBase {
    bytes32 public TEST_BLOCK_HASH = hex"8696a7e4c7a24b94a476e17b472b1ca399a3945d0ff601a3bf97b27d135284e7";
    bytes public BLOCK_INFO_BYTES =
        hex"f90227a009058535822e465292d1f84022621889921b9583eefdcd1e407481fe327c199ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944123c277dfcbdddc3585fdb10c0cee3ce9bbbcf1a0be5ce28db63ad7b63b2f23c205e35659bb7df594527d35af9d8d422b415c30e0a03d53df9c52bede608cd3cfe8c470bff1ba3eb3f79f73a2101132a365ca4868dba0daca9199619168c44a2166a42e1faf1c0d3952b1dc4b0496d11614e304aaa3aeb9010010280884002000480002890988000040008840000640584600010404000010100240000002002100090b08e01001800000120700000160442a108600102c640100404128cc0124890858009a8008882002430040036400020008000488240020000400eb0602a080240000808020c800840100082032010012024810000a20c00402203601042008204803204100400040011523284502080201134004228040032804084003220802009102000c2001204002008200018040500a2420204000809450021800082000000380001082280500000400000110508143006004634010108380802000014882130a0080080002001480603086414448984400600230808394b4488401c9c3808373e9a584650ee5588a4e65746865726d696e64a03edf132c4599d1e4375a9ddb7006554c962c46713a39d9161b2a205565a39b6e8800000000000000000ba0041dd68736473ba6278c4d37781af5484dfeb25a2d07f67d4e33730932255215";
    bytes32 public TEST_STATE_ROOT = hex"be5ce28db63ad7b63b2f23c205e35659bb7df594527d35af9d8d422b415c30e0";
    bytes32 public TEST_SLOT = hex"b8e644bb648df55d79b96f2d1198b27e71c266bfc0128bf0e4b1dc73c59e3096";
    bytes public TEST_ACCOUNT_PROOF =
        hex"f90cd3f90211a06c68b3ef497eca0d38404aaa92abebda35840bdc105fe180601ba231df3c307da0fa07ce024b1e736848285264dab31960dedd489ddbd2135c55cf707a14d0ae1ea02d63a9dfb00e69f27d65556739c0d778f935c980ee1a4bea2737bc401bc25090a096e9e4115747398fb8ae8c1beeaabf3ea69a6c86aab0c147f6aa934420aa8a4aa01019371c03a8b67a227c2c02c47dac7ddee9090c06a248502e15b9249b023acca0f6797c8d4f33ce2a052c04ecdb532970a401271be189365342a52a264c52e467a0928233e82fe7acc406c4bae31f3fcc0f9c57dda61c70368bdd5eb6d08528c01ea0b103558dbe9e65f593ce832fbc7b673c6525c9fb6dfe587b123a22b314c4527aa00c3f030a359f8c329fd9249e8dbe19ff23104019b597114429130ec35fc0f937a0b3b00c4952514e30c6391fa910b7e24674695f22a199cc66e23f3a878d7e415ba0b1d5e15fbbd20b715ca85bc439cf13cb94741ae6889c65f16449aa0aae83c62ca05581f96cc83196777576fae0cc3579010b449e00256942853f20072ee4033e47a0bc0831dafb08372f6070445db624e4ce3d6a10570ade6f5a87f1b5baf6b640e1a066fc24469725c37afc4e15a59ce2551d86e0978d62657c06d031010045749173a098fcf79fee71ee4d2b8c3aa8f098cbaadc295d3cad9319735f99d40a97824bd3a0667f2add04d8ea58e0d89afda407a3ec3e3d84707e9f3075928de32aa20ec37e80f90211a091a45a724544e58542988037084a76a1b195a23eba5b5c1f06d0f083ec0979e9a097b241d574ed634a9a74c1a28f7b0727c94d8d92f7421b37c0e19df925b51033a0960a0be1b76ccc031fa0dcaedc09a1e6c9d2ad24ea47abf80895f9f3b6ecdec4a040361eb320487f646ff7cb138cb858d630daf382f470da18815de4ef73338b56a04cd66496206755e4f7b97bb728f538f26991be91902147819761963ba38fbf66a03527a08ba24044631700f16d2b5ea4140a2ec46cdb6b3491e9f048c33bbd3148a0a600b8633f95a77af80ffea431e6b498ed1dda2ae350a78b04a1fc133bed3a8ba06ef38b726e11355e132b0ecfbce913630334a054215c28dae5da9e257a9902e4a07d64b3366ff933aa950c5cfe06b23243343b16dda3a21990e951e314f363364ea0e357cb027b53a8f7a3cbb191f0c0e2bb1dec969901baa0c867e465357c8fe579a0871ed22026648dca97a24b8359ea8b9d866b6e32239e83553671c79c1c647866a06ab6e70beada3497cd8b468766fa7fd7898c87b1b44db1ba952be249f7a90adba00c0684e9f40cb99747d64ba05efc9aa54d23a667bbe67cdcf577cd6045c6af20a0c360ba5c1bb4d1478565459405ba701e5892e62de26d862a8de58002191b98d7a01a5f09a245a5661317e4f7db5086fedcb7d5e6d233f8d31d92efa8fa6d990edba0181cd3dcbfff9e53661debf8a2086b7a7a973a06e005f6a18f8ae888ea1a374e80f90211a0ef1d48bca25e43cb31607b292ff9477258ddbba240cc46a557f916c3d970162da0bd54cf60c10e1cf9e66a58dbbe4a7972530b186dc9b0ccfca9da8d54accf5770a0dd7e8ead4e3d38fa3b60e42863bba6e59d2d40bea3b2a2597d5f7d93c48fee8da020a21fd424a1ee4a1df5a0ef7a8b944f286405cda339484845ad4d31f32862bca0e898281b543e6512b0935ed219e438caa593fcae2c29f890780bbe2def4a0a1ca00646590913d3d7c0812088d1068123222da7756fe6270c43a287e0fe20a30117a0d266f72db8b2b2258922566e96eeec78b334810f1961dc238b20ed72268efceea03098970dd8f43b9fcd218c11fd9faa544819fa37b444f2e6fd5b70352b4e717fa0f7a7c4a37d3ec5867663b104f236e46c8946e94b6e01c6fd27687b7fe3ccdcc9a052b096360cc013464c99eebf66f80d41f6289275db3f3c0a61f4c41f8bb13290a0083eaae68d63307586a2738e6d2b0394eb45aaf9c0870bbd590fc44a43154f38a0e55fcfcab51ab67a99760d0adf219d37e40d8a6b62e626dbec45265e2296f3fca09676f3352d9a5411a290eca3424ec7262bb7252fc7500072376a792dbe18e608a074389b9189906b3b63282fdb7315a2a45d83eab257b374a230d05935de2156afa0cd4ae181e411b23eee4b313205a56a984f84e85ede2222dc78b1cf992356476ca0a643dce7ff1ce163b672471ff4406ed2d793f95600a4caf52116796c31ed74e180f90211a024b27f61cb24b9459ecb4fe642567e62aa165d5d8263b93c7e97b2712aa4dc6da06378efceb593ac2ec3581409d3056fd449da87651b71833ec3c65df6ed2a2903a02676fd677360db5a7f9b9484716a2298694fb68cfd4c90014057c40ae4430ae0a0c59c5a85b1a05ee268fcb84982c043871ed4534d2ff461719d8767a7fad761e0a01924f4ceff0e9cc1e064f4548901861643c38dd601f02fcc021eda767b838277a0530e14ba5bc91614fb6b2ad806997e8f45d84e56ee22ffce461f47d46bbc031aa070ed445d8b0f44c5d1d5852d5de9eb4463d61a43b95574f291bf8c2ff0798a91a056f3b7d2b3bfe6842863cc9e93e7f4414e8392d32379c4f66405e85ab90c10a6a017596992661d579a3c46ec7cc6443ab9de1e787fbda69d2837496aab1d225c34a09f7496f03d3b0063b8ab2ccbc122fc17bed84bba081e0c5901bd6a3293c375cea087af975e9cefb2413c418dda55579114f7a0dc5580ed9bb44eb9ca61676da0a0a074026d17effb134253012739fb8459c0ff86f517e5307e1589a9a89e6d297004a0ea7100829b5a4bcbbe021ad71f974c020f1d7c404c453ea1b29aa64fdb7aa10aa048647d49d04d92ede0a0a766038d6a3b9ac218536d87096781cc65dc79ceb421a0f9482ce4801662256f6a199ef0b37d0bc09f5ee4143f53bc4278b75852ffcb7ba033323336b10a4c6f97ef12de00e60bd79dc2f325c57989f6c37907f554e8bc8880f90211a0ed5339e74ff6c6fdf018bcda7f0f7ccab2f996ce74d3cf7647916dafc30da7eba08517500aeba18f3dc81e408ff26ae986caf4cb6b6612814c25d5ff14b7f13397a0c57353cd2fff16a1d91e0802a511139450ed7853b37c5cbadf5f7d335594d0fda08ae0af08c914b207bfa4f6217a16bbb0618afdba367cfad833a8e03d96b9bef2a0cb0bd4d0b6caf27209e965540fe8ea11b2c0766fc769d42a10372e70db584220a0199796dcc38fadfba05bd5053c53320fbdf21adcb1f0144c816473729de2dc51a0fd4a9cdbf2f47ac2a667c92524a2879337a6dc5df23ae4bd7ec2dc552187ad25a0689e71fb7629dece3470edc81c3dcd70e77d26bfc0a4f71b95e4f53606e3b93fa0d6be6dafd1deeb175da165be249056998f5cc0edec8467155955c09c9502f84fa0c51e41b163a089e3d24b75f27d2ad80d317b0e015fd99bbf364ca75db2120c27a09aca5638cd6ae066119c7d22dee83649e67f0dd11f8e2763c229d3fdbbd06065a096be25c50167a4b24475d71535d33bc39701e273dd62d69fa2ec7c98f9f60b4aa06cf95ac5e722760ef6a3eedcb58b7195584f83d82a985b3f59868b991cb272e4a0a38524b07946d22e267a86ebfdca4b613102f987fbf763f2b7e73a126d937ebca0b300cc5614a4375a0cb56cde8b19f79734d65218f4a54789c3e0485c7655b61ea03284337fdcf55d31332d498a2f82f9075a7cad18693418b3c3a7582d9422e78280f901b1a0eda8e20a4aa74a91ffa84eeaa24f78750de341586deee94d6554196ff66ac75080a0c67ca3261ee48f08fb7a0924ab892109aac5fe18f2cec9da638f98450bde609ca032af8aaf791d62b5dd34e3c820f48969bb9610679fb2ae915c61dfe7a75da44ca09cf66822b47ad8e593614ee0fb79bd209df789609676fb907793dba01ed2cfa0a0a03ba3567c76485cfb3e3600884152d39b54da2aa6ffbba388f3b7dbe588a7ada07c10036f63c48fd47a50212d05d228a44c43ecec3e10750a770b4354bed09ba0a04e3bf9bb7591dbff93dfe4d0dd03537664a6d9a892b26b05b89c7b510235f889a0ebd74f88ce76fd0d0e146d6cdb5d906e3f18969e4fc02acf5934ca9f81d810f5a0dbdc2592ede452ad3b188f07a0fb8e6bb381587ca757f55d86dc1a3f48fbe99ba0018df8f58227467a39589dc7b9fa67a88e386e78349f14d8ecd3b7a63dd7451c80a09e0b67a5690fb693d795812a700e5e35372988bb1d550163355860effe01d48480a0f936750c9efb849d83f9f55dbc1b256771d21adf221625ef1ee6712257428ffaa0caed5009bb52fbd56871d4aad4119e81993da97b609432846ec3cab010a2300880f851808080808080808080a09bd97b637933f34507054718e9a2e7d7946c7ac75270be9313ec1abb8e50837e808080a01d4d8bff1844c765bd10f60f2a975afe6103f23b1b0bda497530eb4a9a34859f808080f8669d388447052349eafe1b500009bc7ddc9af6bce223aa4f04ba87fbce7979b846f8440180a09cccc0ba90d9282de0f512556414a39fdff073b1884f17f552c4f58dc5f6f63da0f651d18f1d492e2a3f41f587b0b273240dd8b90b6dd22419604f416c8167b39a";
    bytes public TEST_KEY_PROOF =
        hex"f898f8518080808080808080808080a0338bab1c10db5d6387b8a0c938ebc2167e0f198e3621a8127eee7e81b11b391d80a01fba58ac8ec292dd229c0d58c3c0c2e63e95eb5d1e9e446b8a24b21a40ea26c1808080f843a032a549da69802f7989f0b49cafb7a0d6bd610894e1a85a25ab8d1f7f3af2d077a1a08921e8ed690b7f8403ab4309004d5b6228691f0c3e658646aec40fafb5d53ed8";
    address public TEST_NEW_OWNER = 0x8356007A25A2f818e1560D4F059be07550dEf70A;
    uint256 public TEST_BLOCK_NUMBER = 9745480;
    address public TEST_L1_KEYSTORE = 0xdc2C9b6cF8B8DfBE46292Ac4A8A354Ec3C9A231b;
}
