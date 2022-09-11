
use std::collections::HashMap;

use keyphrase::{group_ciphertext, calculate_ioc};
use decode_given_length::{decode_given_length};
const DELTA: f64 = 0.007;
const ENGLISH_IOC: f64 = 0.068;

const KEY_MULTIPLE: usize = 3; // how many multiples of the candidate key length we will test
fn main() {
    println!("Hello, world!");
}

pub fn decode(ciphertext: &str) -> String {


    let (candidate_length, buckets) = determine_key_length(ciphertext);

    let plaintext = decode_given_length(ciphertext, candidate_length, buckets);



    plaintext
}
/*
    This function takes in ciphertext as input and determines good candidate
    for key length period by testing from length = 2 onwards and calculating 
    Index of Coincidence for the ciphertext each time. When the IOC is within an 
    acceptable range in comparison to IOC for English texts, we return this candidate
    as the key length period.
*/
pub fn determine_key_length (original_ciphertext: &str) -> (usize, Vec<HashMap<char, usize>>) {

    let mut candidate_length: usize = 2;
    let ciphertext = original_ciphertext.to_ascii_uppercase();

    let mut ioc_total: f64 = 0.0;
    loop {

        let buckets = group_ciphertext(&ciphertext, candidate_length);
        let group_length = buckets.len();

        for bucket in buckets.iter() {
            ioc_total += calculate_ioc(bucket);
        }
        let _ioc_avg = ioc_total / group_length as f64;
        eprintln!("{} / {} = {}", ioc_total, group_length, _ioc_avg);

        if ENGLISH_IOC - DELTA <= _ioc_avg { //&& candidate_length >= 
            return (candidate_length, buckets);
        }


        ioc_total = 0.0;
        candidate_length += 1;
    }
}

















#[cfg(test)]
mod tests{
    use keyphrase::{group_ciphertext, calculate_ioc};
    use super::*;
    /* 
    #[test]
    fn key_length_() {
        let mut ciphertext = String::from("");
        ciphertext.make_ascii_uppercase();
        assert_eq!( , determine_key_length(&ciphertext));
    } 
    */
    #[test]
    fn key_length_14() {
        // key is methoxybenzene
        let mut ciphertext = String::from("Flx sckc mezo tbwf sy avb moi-fsvrif xhdb cjjgxdvrh, zsm xifrf hrzh oyf hxmwkguiyx sa mfw phm lsu. Whhxpeei uf vbp tmqd, wui bebk bl ffiq ss glq pbnvq, rii fsvrif sk avb rpaa. Z gnv iel jcjgok qnaa xti lafbcu eac avxt lxy ook pygrxeifgalr xle xutqo mz xal ofp, tlr geq e bptu.");
        ciphertext.make_ascii_uppercase();
        assert_eq!( 14, determine_key_length(&ciphertext).0);
    } 
    #[test]
    fn key_length_9() {
        // key is JUDGEMENT
        let mut ciphertext = String::from("Cbh rszi ytvj suwf ss mqy rti-exexnn wuaz jyblehxip, rbm zolzi pinw kow jirmabcyoe sz mgl fub uyf. Whbcwdyi nc uxa mlji, elr ijcg ts tirw ci wni xmtac, nkk wfvrxc iu zlq xbpw. U fgv ief vxgltk psjg cbh yxdirm jhg cmfl uxa uus sgxfmaywilqh ngm nkaqn ma mqy dov, elr ajx d vpmr.");
        ciphertext.make_ascii_uppercase();
        assert_eq!(9 , determine_key_length(&ciphertext).0);
    } 
    #[test]
    fn key_length_8() {
        // key is SECURITY
        let mut ciphertext = String::from("Llg zrkm rzev lvxxylmpa cmmrwvu wrv uc xswhu uxyfw vqf bagfku: yzbacj e uudm lciyghtm hd divnvz hd llg jcibllizn za vpqtvyu ebrz xjy jifc hetn fn mfw ogs, vqmfwv fcwnxpwrv mvyncfggm cmmrwvu uim vpqtvyu ebrz hkzwmkcfx ruibl mx xjy bmr zmx vbvg xlvw yckp mfw wcgv kkwhxgx cmmrwvu. Nyql qwgqhu xhqkmdccqmw aw rifzew hvqvrjec.");
        ciphertext.make_ascii_uppercase();
        assert_eq!(8, determine_key_length(&ciphertext).0);
    }
    #[test]
    fn key_length_6() {
        // key unknown
        let mut ciphertext = String::from("TYWUR USHPO SLJNQ AYJLI FTMJY YZFPV EUZTS GAHTU WNSFW EEEVA
        MYFFD CZTMJ WSQEJ VWXTU QNANT MTIAW AOOJS HPPIN TYDDM VKQUF
        LGMLB XIXJU BQWXJ YQZJZ YMMZH DMFNQ VIAYE FLVZI ZQCSS AEEXV
        SFRDS DLBQT YDTFQ NIVKU ZPJFJ HUSLK LUBQV JULAB XYWCD IEOWH
        FTMXZ MMZHC AATFX YWGMF XYWZU QVPYF AIAFJ GEQCV KNATE MWGKX
        SMWNA NIUSH PFSRJ CEQEE VJXGG BLBQI MEYMR DSDHU UZXVV VGFXV
        JZXUI JLIRM RKZYY ASETY MYWWJ IYTMJ KFQQT ZFAQK IJFIP FSYAG
        QXZVK UZPHF ZCYOS LJNQE MVK");
        ciphertext.make_ascii_uppercase();
        assert_eq!(6, determine_key_length(&ciphertext).0);
    }
    #[test]
    fn key_length_5() {
        // key unknown
        let mut ciphertext = String::from("ZQQTK PQUWD PGMWD BQTXY LFQWL SHAJB UCIPV KUQEJ RBAAC LRSIZ ZCRWT LDFMT PGYXF ISOSE ASZXN PHTAY HHIIR ADDIJ LBFOE VKUWW VFFLV TCEXG HFFXF ZVGXF BFQEI ZOSEZ UGFGF UJUGK PCZWZ UQQJI VAFLV CSDCX YOPYR SQTEI HQFII VTAYI LRGGR AWARN LAGWK JCZXZ UIMPC FTAVX LHMRU LAMRT PDMXV VIDWV SJQWW YCYOE VKXIU NSBVV CWAYJ SMMGH BWDIU DSYYJ AGQXR ZWPIF SRZSK PCZWR URQQS YOOIW YSELF USEEE KOEAV SSMVE DSYYJ APQHR PZKYE SSMVE PBSWF TSFLZ UUILZ JVUXY HGOSJ AIERF ZAMPC SONSL YOZHR ULUIK FHAET XIUVV HBPXY PGPMW MWOYC AMMXK HQTIJ PHEIC MAAVV JZAWV SMFSR UOSIZ UKTMT ODDSX YSEWY HGSEZ USPEJ AFARX HGOIE KSZGP VJQVG YSVYU PQQEE KWZAY PQTTV YGARJ HBPXY PBSWR YSPEP IMPEP MWZHZ UUFLV PFDIR SZQZV SWZPZ LIAJK OSUVT VBHIE AWARR SJMPL LHTIJ HAQTI PBOMG SSEAY PQTLR CSEAV WHMAR FHDEU PHUSE HZMFL ZSEEE KKTMT OODID HYURX YOBMU OOHST HAARX AVQVV CSZYV ZCRWZ USOYI PGFWR UREXI PDBME NHTIK OWZXR DRDCM LWXJI VAMXK YOOXZ CSEYG LFEXZ AWARJ HFQAF YYURX HGMGK PJQPP PBXMK LFMXL YSMWZ UGAGZ LHKXY LQDIU BZUXP VTARV DFUXV YCDXY LDMVK POXMK FCREE VHTII MWZHJ HGBSN LFRYC HHAYT OGFSE LOZHR ZKTSC LGAQV HQTEJ AWEID LBFME AVQLV HZFLP ZQQTK PQUWD VTMXV TDQVR ASOPR ZGAJR UHMKF UWEXJ HGFLV KFQED ZCRGF UGQVM HHUWD VFFLV PABSJ AIDIJ VTBPL YOXMJ AGURV JIDIJ PBFLV JVGVT OVUWK VFKEE KHDEU PHUSE DVQXY LFAJR UQUIE ACDGF TDMVR AWHIC FFQGV UHFMD LGMVV ZINNV JHQHK VJQVP KWRJV YSZXY HBPPZ UURVF THTEK DVUGY AVQME KIXKV UQQSI JFQHL SWFCF MTAVD LFMKV ZQAYC KOXPF DAQVV ZHMXV TSZXJ HFQNV HZAYJ SMIEK JVQHR URFLV TCFMM LGAJK OSIVZ ASDJF YAMWZ TDAVK HBFEE PBSVV KWQRK PBFLV HBMPP ZWESW OWELZ ZHAVP HGFLV MOOXJ OSDIT VFPWG YCNES PZUXP PGMTF DSDJL SOZHK YCGFC LGAQV ASEXR URUXZ ZPKXY PGFVF BPXIJ VAQWK HBPEI KHTEK HZMVX LDAVK PCZSW OWEXF YWOEC LJUHV UQQMJ ZWRXV KQARJ PGFIE JMUWE VZQWJ WSDXZ UOOMF BGMRU LLMGK PBSME PHEHV TOZHJ PBNVZ LTFSN YWFIR OWEXF YMIID BGFOE VKYSI LHTEE TSDIW HQFWY BAMRE HHGVV CWQAV KIZHV YOZME KIOXZ VBAJV EHQRU LRQBG LFUIE JSUWK OSNIJ AVQPG ACFLV JFUXZ JWEQF MVGQR UVUWK VFKLZ ZHAVZ JOXGY HFMGK LFEGR UCZPP ISQWK PAMXV KPKXY LGFEE KODHN OWOLY BAMRV EDQVZ LBOIN OSFLV YOOXL HZAVK YOPMK PCZEI FVMWW BFZMJ OSPXF MCDQT VFDIT AJUIN ZCRME KWHMU BOXWN LAGWK YSSEI KHTID HGRSI TWZKG HFFWF MOSVV HHILF SSIID BGFQV HGGVV AVQQS FHTIZ YFQPR AWARK VHTID HGESW ISURX ZPKAY VAFLV FODIJ BFDSL URQHR URURT VBFID WZMXZ UUFLV PBOMU LBFWZ UHTIZ YZUZV ZCDGF URUXZ VBILZ JVFVR KWFMF UVMWY HBPIU KCIRK VIEAV TIEXI HHTII JCZWZ KSDXY LUQRV YOXFV HFURX VTFLV DVAPV UODVR AWHIK OOZXY LFQWG LQFMM LDDSS HPUPZ AMAJZ AGPIK HWXW");
        ciphertext.make_ascii_uppercase();
        assert_eq!(5, determine_key_length(&ciphertext).0);
    }
}