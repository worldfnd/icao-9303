//! See <https://www.rfc-editor.org/rfc/rfc5114#section-2.1>
//! All these groups are of prime order with a generator for a prime-order
//! subgroup.

use {
    super::{
        mod_ring::{UintExp, UintMont},
        modp_group::ModPGroup,
    },
    ruint::{
        aliases::{U1024, U160, U192, U2048, U256, U384},
        uint, Uint,
    },
    subtle::ConditionallySelectable,
};

type U224 = Uint<224, 4>;
type U521 = Uint<521, 9>;

/// Mod-P groups
pub struct Group<U, V> {
    pub modulus:   U,
    pub generator: U,
    pub order:     V,
}

/// Elliptic curve groups
pub struct Curve<U, V> {
    pub modulus:   U,
    pub param_a:   U,
    pub param_b:   U,
    pub generator: (U, U),
    pub order:     V,
}

/// RFC 5114 1024-bit MODP Group with 160-bit Prime Order Subgroup
const GROUP_1: Group<U1024, U160> = uint!(Group {
    modulus: 0xB10B8F96_A080E01D_DE92DE5E_AE5D54EC_52C99FBC_FB06A3C6_9A6A9DCA_52D23B61_6073E286_75A23D18_9838EF1E_2EE652C0_13ECB4AE_A9061123_24975C3C_D49B83BF_ACCBDD7D_90C4BD70_98488E9C_219A7372_4EFFD6FA_E5644738_FAA31A4F_F55BCCC0_A151AF5F_0DC8B4BD_45BF37DF_365C1A65_E68CFDA7_6D4DA708_DF1FB2BC_2E4A4371_U1024,
    generator: 0xA4D1CBD5_C3FD3412_6765A442_EFB99905_F8104DD2_58AC507F_D6406CFF_14266D31_266FEA1E_5C41564B_777E690F_5504F213_160217B4_B01B886A_5E91547F_9E2749F4_D7FBD7D3_B9A92EE1_909D0D22_63F80A76_A6A24C08_7A091F53_1DBF0A01_69B6A28A_D662A4D1_8E73AFA3_2D779D59_18D08BC8_858F4DCE_F97C2A24_855E6EEB_22B3B2E5_U1024,
    order: 0xF518AA87_81A8DF27_8ABA4E7D_64B7CB9D_49462353_U160,
});

/// RFC 5114 2048-bit MODP Group with 224-bit Prime Order Subgroup
const GROUP_2: Group<U2048, U224> = uint!(Group {
    modulus: 0xAD107E1E_9123A9D0_D660FAA7_9559C51F_A20D64E5_683B9FD1_B54B1597_B61D0A75_E6FA141D_F95A56DB_AF9A3C40_7BA1DF15_EB3D688A_309C180E_1DE6B85A_1274A0A6_6D3F8152_AD6AC212_9037C9ED_EFDA4DF8_D91E8FEF_55B7394B_7AD5B7D0_B6C12207_C9F98D11_ED34DBF6_C6BA0B2C_8BBC27BE_6A00E0A0_B9C49708_B3BF8A31_70918836_81286130_BC8985DB_1602E714_415D9330_278273C7_DE31EFDC_7310F712_1FD5A074_15987D9A_DC0A486D_CDF93ACC_44328387_315D75E1_98C641A4_80CD86A1_B9E587E8_BE60E69C_C928B2B9_C52172E4_13042E9B_23F10B0E_16E79763_C9B53DCF_4BA80A29_E3FB73C1_6B8E75B9_7EF363E2_FFA31F71_CF9DE538_4E71B81C_0AC4DFFE_0C10E64F_U2048,
    generator: 0xAC4032EF_4F2D9AE3_9DF30B5C_8FFDAC50_6CDEBE7B_89998CAF_74866A08_CFE4FFE3_A6824A4E_10B9A6F0_DD921F01_A70C4AFA_AB739D77_00C29F52_C57DB17C_620A8652_BE5E9001_A8D66AD7_C1766910_1999024A_F4D02727_5AC1348B_B8A762D0_521BC98A_E2471504_22EA1ED4_09939D54_DA7460CD_B5F6C6B2_50717CBE_F180EB34_118E98D1_19529A45_D6F83456_6E3025E3_16A330EF_BB77A86F_0C1AB15B_051AE3D4_28C8F8AC_B70A8137_150B8EEB_10E183ED_D19963DD_D9E263E4_770589EF_6AA21E7F_5F2FF381_B539CCE3_409D13CD_566AFBB4_8D6C0191_81E1BCFE_94B30269_EDFE72FE_9B6AA4BD_7B5A0F1C_71CFFF4C_19C418E1_F6EC0179_81BC087F_2A7065B3_84B890D3_191F2BFA_U2048,
    order: 0x801C0D34_C58D93FE_99717710_1F80535A_4738CEBC_BF389A99_B36371EB_U224,
});

/// RFC 5114 2048-bit MODP Group with 256-bit Prime Order Subgroup
const GROUP_3: Group<U2048, U256> = uint!(Group {
    modulus: 0x87A8E61D_B4B6663C_FFBBD19C_65195999_8CEEF608_660DD0F2_5D2CEED4_435E3B00_E00DF8F1_D61957D4_FAF7DF45_61B2AA30_16C3D911_34096FAA_3BF4296D_830E9A7C_209E0C64_97517ABD_5A8A9D30_6BCF67ED_91F9E672_5B4758C0_22E0B1EF_4275BF7B_6C5BFC11_D45F9088_B941F54E_B1E59BB8_BC39A0BF_12307F5C_4FDB70C5_81B23F76_B63ACAE1_CAA6B790_2D525267_35488A0E_F13C6D9A_51BFA4AB_3AD83477_96524D8E_F6A167B5_A41825D9_67E144E5_14056425_1CCACB83_E6B486F6_B3CA3F79_71506026_C0B857F6_89962856_DED4010A_BD0BE621_C3A3960A_54E710C3_75F26375_D7014103_A4B54330_C198AF12_6116D227_6E11715F_693877FA_D7EF09CA_DB094AE9_1E1A1597_U2048,
    generator: 0x3FB32C9B_73134D0B_2E775066_60EDBD48_4CA7B18F_21EF2054_07F4793A_1A0BA125_10DBC150_77BE463F_FF4FED4A_AC0BB555_BE3A6C1B_0C6B47B1_BC3773BF_7E8C6F62_901228F8_C28CBB18_A55AE313_41000A65_0196F931_C77A57F2_DDF463E5_E9EC144B_777DE62A_AAB8A862_8AC376D2_82D6ED38_64E67982_428EBC83_1D14348F_6F2F9193_B5045AF2_767164E1_DFC967C1_FB3F2E55_A4BD1BFF_E83B9C80_D052B985_D182EA0A_DB2A3B73_13D3FE14_C8484B1E_052588B9_B7D2BBD2_DF016199_ECD06E15_57CD0915_B3353BBB_64E0EC37_7FD02837_0DF92B52_C7891428_CDC67EB6_184B523D_1DB246C3_2F630784_90F00EF8_D647D148_D4795451_5E2327CF_EF98C582_664B4C0F_6CC41659_U2048,
    order: 0x8CF83642_A709A097_B4479976_40129DA2_99B1A47D_1EB3750B_A308B0FE_64F5FBD3_U256,
});

/// RFC 5114 192-bit Random ECP Group, NIST P-192, secp192r1
const CURVE_1: Curve<U192, U192> = uint!(Curve {
    modulus:   0xffffffff_ffffffff_ffffffff_fffffffe_ffffffff_ffffffff_U192,
    param_a:   0xffffffff_ffffffff_ffffffff_fffffffe_ffffffff_fffffffc_U192,
    param_b:   0x64210519_e59c80e7_0fa7e9ab_72243049_feb8deec_c146b9b1_U192,
    generator: (
        0x188da80e_b03090f6_7cbf20eb_43a18800_f4ff0afd_82ff1012_U192,
        0x07192b95_ffc8da78_631011ed_6b24cdd5_73f977a1_1e794811_U192,
    ),
    order:     0xffffffff_ffffffff_ffffffff_99def836_146bc9b1_b4d22831_U192,
});

/// RFC 5114 224-bit Random ECP Group, NIST P-224, secp224r1
const CURVE_2: Curve<U224, U224> = uint!(Curve {
    modulus:   0xffffffff_ffffffff_ffffffff_ffffffff_00000000_00000000_00000001_U224,
    param_a:   0xffffffff_ffffffff_ffffffff_fffffffe_ffffffff_ffffffff_fffffffe_U224,
    param_b:   0xb4050a85_0c04b3ab_f5413256_5044b0b7_d7bfd8ba_270b3943_2355ffb4_U224,
    generator: (
        0xb70e0cbd_6bb4bf7f_321390b9_4a03c1d3_56c21122_343280d6_115c1d21_U224,
        0xbd376388_b5f723fb_4c22dfe6_cd4375a0_5a074764_44d58199_85007e34_U224,
    ),
    order:     0xffffffff_ffffffff_ffffffff_ffff16a2_e0b8f03e_13dd2945_5c5c2a3d_U224,
});

/// RFC 5114 256-bit Random ECP Group, NIST P-256, secp256r1
const CURVE_3: Curve<U256, U256> = uint!(Curve {
    modulus:   0xffffffff_00000001_00000000_00000000_00000000_ffffffff_ffffffff_ffffffff_U256,
    param_a:   0xffffffff_00000001_00000000_00000000_00000000_ffffffff_ffffffff_fffffffc_U256,
    param_b:   0x5ac635d8_aa3a93e7_b3ebbd55_769886bc_651d06b0_cc53b0f6_3bce3c3e_27d2604b_U256,
    generator: (
        0x6b17d1f2_e12c4247_f8bce6e5_63a440f2_77037d81_2deb33a0_f4a13945_d898c296_U256,
        0x4fe342e2_fe1a7f9b_8ee7eb4a_7c0f9e16_2bce3357_6b315ece_cbb64068_37bf51f5_U256,
    ),
    order:     0xffffffff_00000000_ffffffff_ffffffff_bce6faad_a7179e84_f3b9cac2_fc632551_U256,
});

/// RFC 5114 384-bit Random ECP Group, NIST P-384, secp384r1
const CURVE_4: Curve<U384, U384> = uint!(Curve {
   modulus: 0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_fffffffe_ffffffff_00000000_00000000_ffffffff_U384,
   param_a: 0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_fffffffe_ffffffff_00000000_00000000_fffffffc_U384,
   param_b: 0xB3312FA7_E23EE7E4_988E056B_E3F82D19_181D9C6E_FE814112_0314088F_5013875A_C656398D_8A2ED19D_2A85C8ED_D3EC2AEF_U384,
   generator: (
        0xAA87CA22_BE8B0537_8EB1C71E_F320AD74_6E1D3B62_8BA79B98_59F741E0_82542A38_5502F25D_BF55296C_3A545E38_72760AB7_U384,
        0x3617DE4A_96262C6F_5D9E98BF_9292DC29_F8F41DBD_289A147C_E9DA3113_B5F0B8C0_0A60B1CE_1D7E819D_7A431D7C_90EA0E5F_U384,
   ),
   order: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_C7634D81_F4372DDF_581A0DB2_48B0A77A_ECEC196A_CCC52973_U384,
});

/// RFC 5114 521-bit Random ECP Group, NIST P-521, secp521r1
const CURVE_5: Curve<U521, U521> = uint!(Curve {
    modulus: 0x000001FF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_U521,
    param_a: 0x000001FF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFC_U521,
    param_b: 0x00000051_953EB961_8E1C9A1F_929A21A0_B68540EE_A2DA725B_99B315F3_B8B48991_8EF109E1_56193951_EC7E937B_1652C0BD_3BB1BF07_3573DF88_3D2C34F1_EF451FD4_6B503F00_U521,
    generator: (
        0x000000C6_858E06B7_0404E9CD_9E3ECB66_2395B442_9C648139_053FB521_F828AF60_6B4D3DBA_A14B5E77_EFE75928_FE1DC127_A2FFA8DE_3348B3C1_856A429B_F97E7E31_C2E5BD66_U521,
        0x00000118_39296A78_9A3BC004_5C8A5FB4_2C7D1BD9_98F54449_579B4468_17AFBD17_273E662C_97EE7299_5EF42640_U521,
    ),
    order: 0x000001FF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFA_51868783_BF2F966B_7FCC0148_F709A5D0_3BB5C9B8_899C47AE_BB6FB71E_91386409_U521,
});

impl<U, V> From<Group<U, V>> for ModPGroup<U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    fn from(value: Group<U, V>) -> Self {
        ModPGroup::new(value.modulus, value.generator, value.order).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::crypto::mod_ring::{ModRing, RingRefExt, UintExp, UintMont},
        subtle::ConditionallySelectable,
    };

    fn test_modp_order<U, V>(group: Group<U, V>)
    where
        U: UintMont + ConditionallySelectable,
        V: UintMont + UintExp,
    {
        assert!(group.generator < group.modulus);
        let field = ModRing::from_modulus(group.modulus);
        let generator = field.from(group.generator);
        let power = generator.pow_ct(group.order);
        assert_eq!(power, field.one());
    }

    fn test_curve_order<U, V>(curve: Curve<U, V>)
    where
        U: UintMont + ConditionallySelectable,
        V: UintMont + UintExp,
    {
        assert!(curve.param_a < curve.modulus);
        assert!(curve.param_b < curve.modulus);
        assert!(curve.generator.0 < curve.modulus);
        assert!(curve.generator.1 < curve.modulus);
        let field = ModRing::from_modulus(curve.modulus);
        let a = field.from(curve.param_a);
        let b = field.from(curve.param_b);

        // Check non-singular requirement 4a^3 + 27b^2 != 0
        let c4 = field.from_u64(4);
        let c27 = field.from_u64(27);
        assert_ne!(c4 * a.pow(3) + c27 * b.square(), field.zero());

        let generator = (field.from(curve.generator.0), field.from(curve.generator.1));
    }

    #[test]
    fn test_group_1_order() {
        test_modp_order(GROUP_1);
    }

    #[test]
    fn test_group_1_example() {
        let xa = uint!(0xb9a3b3ae_8fefc1a2_93049650_7086f845_5d48943e_U160);
        let ya = uint!(0x2A853B3D_92197501_B9015B2D_EB3ED84F_5E021DCC_3E52F109_D3273D2B_7521281C_BABE0E76_FF5727FA_8ACCE269_56BA9A1F_CA26F202_28D8693F_EB10841D_84A73600_54ECE5A7_F5B7A61A_D3DFB3C6_0D2E4310_6D8727DA_37DF9CCE_95B47875_5D06BCEA_8F9D4596_5F75A5F3_D1DF3701_165FC9E5_0C4279CE_B07F9895_40AE96D5_D88ED776_U1024);
        let xb = uint!(0x9392c9f9_eb6a7a6a_9022f7d8_3e7223c6_835bbdda_U160);
        let yb = uint!(0x717A6CB0_53371FF4_A3B93294_1C1E5663_F861A1D6_AD34AE66_576DFB98_F6C6CBF9_DDD5A56C_7833F6BC_FDFF0955_82AD868E_440E8D09_FD769E3C_ECCDC3D3_B1E4CFA0_57776CAA_F9739B6A_9FEE8E74_11F8D6DA_C09D6A4E_DB46CC2B_5D520309_0EAE6126_311E53FD_2C14B574_E6A3109A_3DA1BE41_BDCEAA18_6F5CE067_16A2B6A0_7B3C33FE_U1024);
        let z = uint!(0x5C804F45_4D30D9C4_DF85271F_93528C91_DF6B48AB_5F80B3B5_9CAAC1B2_8F8ACBA9_CD3E39F3_CB614525_D9521D2E_644C53B8_07B810F3_40062F25_7D7D6FBF_E8D5E8F0_72E9B6E9_AFDA9413_EAFB2E8B_0699B1FB_5A0CACED_DEAEAD7E_9CFBB36A_E2B42083_5BD83A19_FB0B5E96_BF8FA4D0_9E345525_167ECD91_55416F46_F408ED31_B63C6E6D_U1024);

        let group = ModPGroup::from(GROUP_1);
        let gxa = group.scalar_field().from(xa);
        let gya = group.base_field().from(ya);
        let gxb = group.scalar_field().from(xb);
        let gyb = group.base_field().from(yb);
        let gz = group.base_field().from(z);

        assert_eq!(
            group.generator().pow_ct(group.scalar_field().modulus()),
            group.base_field().one()
        );
        assert_eq!(gxa.to_uint(), xa);
        assert_eq!(gya.to_uint(), ya);
        assert_eq!(gxb.to_uint(), xb);
        assert_eq!(gyb.to_uint(), yb);
        assert_eq!(gz.to_uint(), z);
        assert_eq!(group.generator().pow_ct(gxa.to_uint()), gya);
        assert_eq!(group.generator().pow_ct(gxb.to_uint()), gyb);
        assert_eq!(gya.pow_ct(gxb.to_uint()), gz);
        assert_eq!(gyb.pow_ct(gxa.to_uint()), gz);
    }

    #[test]
    fn test_group_2_order() {
        test_modp_order(GROUP_2);
    }

    #[test]
    fn test_group_3_order() {
        test_modp_order(GROUP_3);
    }

    #[test]
    fn test_curve_1_order() {
        test_curve_order(CURVE_1);
    }
}
