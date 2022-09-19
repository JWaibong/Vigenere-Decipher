
use std::{collections::HashMap, io::stdin};

use keyphrase::{group_ciphertext, calculate_ioc};
use decode_given_length::{decode_given_length};
use std::io::BufRead;
const DELTA: f64 = 0.0075; // ERROR TOLERANCE for determining minimum IOC requirement for candidate key length
const ENGLISH_IOC: f64 = 0.068;

fn main() {
    // code snippet to read from stdin taken from
    // https://stackoverflow.com/questions/30186037/how-can-i-read-a-single-line-from-stdin
    let mut ciphertext = String::new();
    let stdin = stdin();
    stdin.lock().read_line(&mut ciphertext).unwrap();
    
    ciphertext.pop(); // pop off LF

    let (key,plaintext) = decode(&ciphertext);
    println!("{}", key);
    println!("{}",plaintext);
}

/*
    This function takes in a piece of ciphertext, determines the best candidate for key length using index of coincidence,
    and then finds the best candidate key using chi-squared and quadrigram testing and then decodes the ciphertext.
*/
pub fn decode(ciphertext: &str) -> (String, String) {
    let (candidate_length, buckets) = determine_key_length(ciphertext);
    let (key,plaintext) = decode_given_length(ciphertext, candidate_length, buckets);
    (key, plaintext)
}

/*
    This function takes in ciphertext as input and determines good candidate
    for key length period by testing from length = 2 onwards and calculating 
    Index of Coincidence for the ciphertext each time. When the IOC is within an 
    acceptable range in comparison to IOC for English texts, we return this candidate
    as the key length period.

    http://practicalcryptography.com/cryptanalysis/text-characterisation/index-coincidence/
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
        //eprintln!("{} / {} = {}", ioc_total, group_length, _ioc_avg);

        if ENGLISH_IOC - DELTA <= _ioc_avg { //&& candidate_length >= 
            return (candidate_length, buckets);
        }
        ioc_total = 0.0;
        candidate_length += 1;
    }
}

















#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn methoxybenzene() {
        let ciphertext = String::from("Flx sckc mezo tbwf sy avb moi-fsvrif xhdb cjjgxdvrh, zsm xifrf hrzh oyf hxmwkguiyx sa mfw phm lsu. Whhxpeei uf vbp tmqd, wui bebk bl ffiq ss glq pbnvq, rii fsvrif sk avb rpaa. Z gnv iel jcjgok qnaa xti lafbcu eac avxt lxy ook pygrxeifgalr xle xutqo mz xal ofp, tlr geq e bptu.");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "METHOXYBENZENE");
        assert_eq!(plaintext, "The lone lamp post of the one-street town flickered, not quite dead but definitely on its way out. Suitcase by her side, she paid no heed to the light, the street or the town. A car was coming down the street and with her arm outstretched and thumb in the air, she had a plan.");
    }
    
    #[test]
    fn theiliadofhomer() {
        let ciphertext = String::from("LPROZOOGRJZGFLVTUKMCWFDQMPZXIJLVRWQXEOSZZHTEKUYSCRPTFCZUHXIJLPPTDCPRBYOSMGYTLEVDUAQMFIFMZVLVYTOQDLHXLBPLLKYCQYODRKSACTEUXZEVOUAQMFOSDSUBKMBJQEORFWFQCKHKSODINGJZSHGVVLMSZDWWHFJAVQGFNUWMWAOIXTCSRYCYPPTPLFUCRAVQHRRVRESQCKHMLGARFYHXZPCSNWSNCRQVGHRLRZEDHFJVUPCXZJQCATISQSCGXNBALWYMAQCYOSD");        let (key, plaintext) = decode(&ciphertext);
        let expected_key = "THEILIADOFHOMER";
        let expected_plaintext = "SINGOGODDESSTHEANGEROFACHILLESSONOFPELEUSTHATBROUGHTCOUNTLESSILLSUPONTHEACHAEANSMANYABRAVESOULDIDITSENDHURRYINGDOWNTOHADESANDMANYAHERODIDITYIELDAPREYTODOGSANDVULTURESFORSOWERETHECOUNSELSOFJOVEFULFILLEDFROMTHEDAYONWHICHTHESONOFATREUSKINGOFMENANDGREATACHILLESFIRSTFELLOUTWITHONEANOTHER";        assert_eq!(key, expected_key);
        assert_eq!(key, expected_key);
        assert_eq!(plaintext, expected_plaintext);
    }

    #[test]
    fn summer_3() {
        let ciphertext = String::from("FIIFL VZOZS VPDCA ZVFSL EMRUL BQISC XVQTS NDMFT IDGIZ ILZDM
        FFLVZ YMHCG DIGSL DSHEZ SIWMM XPNAN TIIRJ SFMWB XIDPS EWHAI
        XYWQM EXVVV DMRUK XASPF OQTUP JLNTQ WTJYQ OLFOF EOVVW WTURX
        DIGPT LLMFT INJYF OLKZU FXMVK CZISV AHDQQ VEVDM RTWIR MWYJI
        GPRFO CFUWK ZYFUQ VGZZU KYLNT MXKZY SDEMW MMXPX SJUZK NAXQQ
        ZVJSA ZICWN ERSIL BTUWJ HLUFI ZFNTQ GYMLO TARQJ MFLJL ISXMU
        WUZPA VXUUD MVKNT MXUGL GZFPL BQFVZ HFQTI TSNQE XVSGR DSDLB
        QBVVK YZOIF XNTQW LFZAX PFOCZ SHRJE ZQWJD CWQEU JYMYR FOUDQ
        JIGFU ORFLU YAYJW MTMPC VCEFY ITNTU WYSFX AAUZI GEIZS GEQRK
        OCFTF IGIYN IWGLQ FSJOY QBXYW XGEXS WBUZH KZYPA SI");
        let (key, plaintext) = decode(&ciphertext);
        let expected_key = "SUMMER";
        let expected_plaintext = "NOWTH EHUNG RYLIO NROAR SANDT HEWOL FBEHO WLSTH EMOON WHILS
        TTHEH EAVYP LOUGH MANSN ORESA LLWIT HWEAR YTASK FORDO NENOW
        THEWA STEDB RANDS DOGLO WWHIL STTHE SCREE CHOWL SCREE CHING
        LOUDP UTSTH EWRET CHTHA TLIES INWOE INREM EMBRA NCEOF ASHRO
        UDNOW ITIST HETIM EOFNI GHTTH ATTHE GRAVE SALLG APING WIDEE
        VERYO NELET SFORT HHISS PRITE INTHE CHURC HWAYP ATHST OGLID
        EANDW EFAIR IESTH ATDOR UNBYT HETRI PLEHE CATES TEAMF ROMTH
        EPRES ENCEO FTHES UNFOL LOWIN GDARK NESSL IKEAD REAMN OWARE
        FROLI CNOTA MOUSE SHALL DISTU RBTHI SHALL OWDHO USEIA MSENT
        WITHB ROOMB EFORE TOSWE EPTHE DUSTB EHIND THEDO OR";
        assert_eq!(key, expected_key);
        assert_eq!(plaintext, expected_plaintext);
    }


    
    #[test]
    fn judgement() {
        // key is JUDGEMENT
        let ciphertext = String::from("Cbh rszi ytvj suwf ss mqy rti-exexnn wuaz jyblehxip, rbm zolzi pinw kow jirmabcyoe sz mgl fub uyf. Whbcwdyi nc uxa mlji, elr ijcg ts tirw ci wni xmtac, nkk wfvrxc iu zlq xbpw. U fgv ief vxgltk psjg cbh yxdirm jhg cmfl uxa uus sgxfmaywilqh ngm nkaqn ma mqy dov, elr ajx d vpmr.");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "JUDGEMENT");
        assert_eq!(plaintext, "The lone lamp post of the one-street town flickered, not quite dead but definitely on its way out. Suitcase by her side, she paid no heed to the light, the street or the town. A car was coming down the street and with her arm outstretched and thumb in the air, she had a plan.");
    } 
    #[test]
    fn an() {
        // key is SECURITY
        let ciphertext = String::from("Tue sapt ghnt eecentvnt lrtgees paa br fbuad zennf tjo ghvnts: righrr n snmr srqheacr os lrtgee os tue clniatrxg if ceyctrd jigh ghr snmr pnrg os tue xel, evtuee dvfseeeat fedurnpef lrtgees nrr ceyctrd jigh qisfrrrng pnrgs bf ghr kry oug tuel eadf wvtu tue faze prlpgeq lrtgees. Ghvs fepoad cofsvbvlvtl if pboell peooaolr.");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "AN");
        assert_eq!(plaintext, "The fact that repeating letters can be found means two things: either a same sequence of letter of the plaintext is crypted with the same part of the key, either different sequences letters are crypted with different parts of the key but they ends with the same crypted letters. This second possibility is poorly probable.");
    }

    #[test]
    fn security() {
        let ciphertext = String::from("Llg zrkm rzev lvxxylmpa cmmrwvu wrv uc xswhu uxyfw vqf bagfku: yzbacj e uudm lciyghtm hd divnvz hd llg jcibllizn za vpqtvyu ebrz xjy jifc hetn fn mfw ogs, vqmfwv fcwnxpwrv mvyncfggm cmmrwvu uim vpqtvyu ebrz hkzwmkcfx ruibl mx xjy bmr zmx vbvg xlvw yckp mfw wcgv kkwhxgx cmmrwvu. Nyql qwgqhu xhqkmdccqmw aw rifzew hvqvrjec.");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "SECURITY");

        assert_eq!(plaintext, "The fact that repeating letters can be found means two things: either a same sequence of letter of the plaintext is crypted with the same part of the key, either different sequences letters are crypted with different parts of the key but they ends with the same crypted letters. This second possibility is poorly probable.");

    }

    #[test]
    fn summer() {
        // key is SUMMER
        let ciphertext = String::from("TYWUR USHPO SLJNQ AYJLI FTMJY YZFPV EUZTS GAHTU WNSFW EEEVA
        MYFFD CZTMJ WSQEJ VWXTU QNANT MTIAW AOOJS HPPIN TYDDM VKQUF
        LGMLB XIXJU BQWXJ YQZJZ YMMZH DMFNQ VIAYE FLVZI ZQCSS AEEXV
        SFRDS DLBQT YDTFQ NIVKU ZPJFJ HUSLK LUBQV JULAB XYWCD IEOWH
        FTMXZ MMZHC AATFX YWGMF XYWZU QVPYF AIAFJ GEQCV KNATE MWGKX
        SMWNA NIUSH PFSRJ CEQEE VJXGG BLBQI MEYMR DSDHU UZXVV VGFXV
        JZXUI JLIRM RKZYY ASETY MYWWJ IYTMJ KFQQT ZFAQK IJFIP FSYAG
        QXZVK UZPHF ZCYOS LJNQE MVK");

        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "SUMMER");
        assert_eq!(plaintext, "BEKIN DANDC OURTE OUSTO THISG ENTLE MANHO PINHI SWALK SANDG
        AMBOL INHIS EYESF EEDHI MWITH APRIC OCKSA NDDEW BERRI ESWIT
        HPURP LEGRA PESGR EENFI GSAND MULBE RRIES THEHO NEYBA GSSTE
        ALFRO MTHEH UMBLE BEESA NDFOR NIGHT TAPER SCROP THEIR WAXEN
        THIGH SANDL IGHTT HEMAT THEFI ERYGL OWWOR MSEYE STOHA VEMYL
        OVETO BEDAN DTOAR ISEAN DPLUC KTHEW INGSF ROMPA INTED BUTTE
        RFLIE STOFA NTHEM OONBE AMSFR OMHIS SLEEP INGEY ESNOD TOHIM
        ELVES ANDDO HIMCO URTES IES");
    }
    #[test]
    fn homer() {
        let ciphertext = String::from("ZQQTK PQUWD PGMWD BQTXY LFQWL SHAJB UCIPV KUQEJ RBAAC LRSIZ ZCRWT LDFMT PGYXF ISOSE ASZXN PHTAY HHIIR ADDIJ LBFOE VKUWW VFFLV TCEXG HFFXF ZVGXF BFQEI ZOSEZ UGFGF UJUGK PCZWZ UQQJI VAFLV CSDCX YOPYR SQTEI HQFII VTAYI LRGGR AWARN LAGWK JCZXZ UIMPC FTAVX LHMRU LAMRT PDMXV VIDWV SJQWW YCYOE VKXIU NSBVV CWAYJ SMMGH BWDIU DSYYJ AGQXR ZWPIF SRZSK PCZWR URQQS YOOIW YSELF USEEE KOEAV SSMVE DSYYJ APQHR PZKYE SSMVE PBSWF TSFLZ UUILZ JVUXY HGOSJ AIERF ZAMPC SONSL YOZHR ULUIK FHAET XIUVV HBPXY PGPMW MWOYC AMMXK HQTIJ PHEIC MAAVV JZAWV SMFSR UOSIZ UKTMT ODDSX YSEWY HGSEZ USPEJ AFARX HGOIE KSZGP VJQVG YSVYU PQQEE KWZAY PQTTV YGARJ HBPXY PBSWR YSPEP IMPEP MWZHZ UUFLV PFDIR SZQZV SWZPZ LIAJK OSUVT VBHIE AWARR SJMPL LHTIJ HAQTI PBOMG SSEAY PQTLR CSEAV WHMAR FHDEU PHUSE HZMFL ZSEEE KKTMT OODID HYURX YOBMU OOHST HAARX AVQVV CSZYV ZCRWZ USOYI PGFWR UREXI PDBME NHTIK OWZXR DRDCM LWXJI VAMXK YOOXZ CSEYG LFEXZ AWARJ HFQAF YYURX HGMGK PJQPP PBXMK LFMXL YSMWZ UGAGZ LHKXY LQDIU BZUXP VTARV DFUXV YCDXY LDMVK POXMK FCREE VHTII MWZHJ HGBSN LFRYC HHAYT OGFSE LOZHR ZKTSC LGAQV HQTEJ AWEID LBFME AVQLV HZFLP ZQQTK PQUWD VTMXV TDQVR ASOPR ZGAJR UHMKF UWEXJ HGFLV KFQED ZCRGF UGQVM HHUWD VFFLV PABSJ AIDIJ VTBPL YOXMJ AGURV JIDIJ PBFLV JVGVT OVUWK VFKEE KHDEU PHUSE DVQXY LFAJR UQUIE ACDGF TDMVR AWHIC FFQGV UHFMD LGMVV ZINNV JHQHK VJQVP KWRJV YSZXY HBPPZ UURVF THTEK DVUGY AVQME KIXKV UQQSI JFQHL SWFCF MTAVD LFMKV ZQAYC KOXPF DAQVV ZHMXV TSZXJ HFQNV HZAYJ SMIEK JVQHR URFLV TCFMM LGAJK OSIVZ ASDJF YAMWZ TDAVK HBFEE PBSVV KWQRK PBFLV HBMPP ZWESW OWELZ ZHAVP HGFLV MOOXJ OSDIT VFPWG YCNES PZUXP PGMTF DSDJL SOZHK YCGFC LGAQV ASEXR URUXZ ZPKXY PGFVF BPXIJ VAQWK HBPEI KHTEK HZMVX LDAVK PCZSW OWEXF YWOEC LJUHV UQQMJ ZWRXV KQARJ PGFIE JMUWE VZQWJ WSDXZ UOOMF BGMRU LLMGK PBSME PHEHV TOZHJ PBNVZ LTFSN YWFIR OWEXF YMIID BGFOE VKYSI LHTEE TSDIW HQFWY BAMRE HHGVV CWQAV KIZHV YOZME KIOXZ VBAJV EHQRU LRQBG LFUIE JSUWK OSNIJ AVQPG ACFLV JFUXZ JWEQF MVGQR UVUWK VFKLZ ZHAVZ JOXGY HFMGK LFEGR UCZPP ISQWK PAMXV KPKXY LGFEE KODHN OWOLY BAMRV EDQVZ LBOIN OSFLV YOOXL HZAVK YOPMK PCZEI FVMWW BFZMJ OSPXF MCDQT VFDIT AJUIN ZCRME KWHMU BOXWN LAGWK YSSEI KHTID HGRSI TWZKG HFFWF MOSVV HHILF SSIID BGFQV HGGVV AVQQS FHTIZ YFQPR AWARK VHTID HGESW ISURX ZPKAY VAFLV FODIJ BFDSL URQHR URURT VBFID WZMXZ UUFLV PBOMU LBFWZ UHTIZ YZUZV ZCDGF URUXZ VBILZ JVFVR KWFMF UVMWY HBPIU KCIRK VIEAV TIEXI HHTII JCZWZ KSDXY LUQRV YOXFV HFURX VTFLV DVAPV UODVR AWHIK OOZXY LFQWG LQFMM LDDSS HPUPZ AMAJZ AGPIK HWXW");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "HOMER");
        assert_eq!(plaintext, "SCEPT ICISM ISASM UCHTH ERESU LTOFK NOWLE DGEAS KNOWL EDGEI SOFSC EPTIC ISMTO BECON TENTW ITHWH ATWEA TPRES ENTKN OWISF ORTHE MOSTP ARTTO SHUTO UREAR SAGAI NSTCO NVICT IONSI NCEFR OMTHE VERYG RADUA LCHAR ACTER OFOUR EDUCA TIONW EMUST CONTI NUALL YFORG ETAND EMANC IPATE OURSE LVESF ROMKN OWLED GEPRE VIOUS LYACQ UIRED WEMUS TSETA SIDEO LDNOT IONSA NDEMB RACEF RESHO NESAN DASWE LEARN WEMUS TBEDA ILYUN LEARN INGSO METHI NGWHI CHITH ASCOS TUSNO SMALL LABOU RANDA NXIET YTOAC QUIRE ANDTH ISDIF FICUL TYATT ACHES ITSEL FMORE CLOSE LYTOA NAGEI NWHIC HPROG RESSH ASGAI NEDAS TRONG ASCEN DENCY OVERP REJUD ICEAN DINWH ICHPE RSONS ANDTH INGSA REDAY BYDAY FINDI NGTHE IRREA LLEVE LINLI EUOFT HEIRC ONVEN TIONA LVALU ETHES AMEPR INCIP LESWH ICHHA VESWE PTAWA YTRAD ITION ALABU SESAN DWHIC HAREM AKING RAPID HAVOC AMONG THERE VENUE SOFSI NECUR ISTSA NDSTR IPPIN GTHET HINTA WDRYV EILFR OMATT RACTI VESUP ERSTI TIONS AREWO RKING ASACT IVELY INLIT ERATU REASI NSOCI ETYTH ECRED ULITY OFONE WRITE RORTH EPART IALIT YOFAN OTHER FINDS ASPOW ERFUL ATOUC HSTON EANDA SWHOL ESOME ACHAS TISEM ENTIN THEHE ALTHY SCEPT ICISM OFATE MPERA TECLA SSOFA NTAGO NISTS ASTHE DREAM SOFCO NSERV ATISM ORTHE IMPOS TURES OFPLU RALIS TSINE CURES INTHE CHURC HHIST ORYAN DTRAD ITION WHETH EROFA NCIEN TORCO MPARA TIVEL YRECE NTTIM ESARE SUBJE CTEDT OVERY DIFFE RENTH ANDLI NGFRO MTHAT WHICH THEIN DULGE NCEOR CREDU LITYO FFORM ERAGE SCOUL DALLO WMERE STATE MENTS AREJE ALOUS LYWAT CHEDA NDTHE MOTIV ESOFT HEWRI TERFO RMASI MPORT ANTAN INGRE DIENT INTHE ANALY SISOF HISHI STORY ASTHE FACTS HEREC ORDSP ROBAB ILITY ISAPO WERFU LANDT ROUBL ESOME TESTA NDITI SBYTH ISTRO UBLES OMEST ANDAR DTHAT ALARG EPORT IONOF HISTO RICAL EVIDE NCEIS SIFTE DCONS ISTEN CYISN OLESS PERTI NACIO USAND EXACT INGIN ITSDE MANDS INBRI EFTOW RITEA HISTO RYWEM USTKN OWMOR ETHAN MEREF ACTSH UMANN ATURE VIEWE DUNDE RANIN DUCTI ONOFE XTEND EDEXP ERIEN CEIST HEBES THELP TOTHE CRITI CISMO FHUMA NHIST ORYHI STORI CALCH ARACT ERSCA NONLY BEEST IMATE DBYTH ESTAN DARDW HICHH UMANE XPERI ENCEW HETHE RACTU ALORT RADIT IONAR YHASF URNIS HEDTO FORMC ORREC TVIEW SOFIN DIVID UALSW EMUST REGAR DTHEM ASFOR MINGP ARTSO FAGRE ATWHO LEWEM USTME ASURE THEMB YTHEI RRELA TIONT OTHEM ASSOF BEING SBYWH OMTHE YARES URROU NDEDA NDINC ONTEM PLATI NGTHE INCID ENTSI NTHEI RLIVE SORCO NDITI ONWHI CHTRA DITIO NHASH ANDED DOWNT OUSWE MUSTR ATHER CONSI DERTH EGENE RALBE ARING OFTHE WHOLE NARRA TIVET HANTH ERESP ECTIV EPROB ABILI TYOFI TSDET AILS");
    }

    #[test]
    fn methoxy() {
        let ciphertext = String::from("Xmyl wpl'f eedovq nitbhfdgp. Mooq umw t sspqar mooq Bmr phg icmvgpbd. Fq eezc ocmpbgsa rtem swcc ielu'h byec. Mowp fmh vvab ye e loczi emgjs ec tew swscp e voookqh eptb. Fq ltasa rtem avfq iel avb rdymo okb ti lafrespxk hl zq ltwdv izsppbd rtem owp yewntdqgarl dsocz'x vvfocox. Al klsxhg'a fbyxmsl ikrup fbqe jmxxy wk jujx avxr flx kwcdugnsh lzextjzbq ti phg cyomgn heyf axys qywmgn otyk xal pbygxr pb ege pbms xr flbz alkqrm dcrjp yeawjyfief axiq lbz zfdq qnjv jmdi ulorrujns. Oij ti dust umw mooq yf xapg jmyiga kxq flta zfdq mlu'h xjierz pbygxbmii.
        Rtikl kxq m vxhgll rsk oso qtcglgp. Chikfckc mwlbabb ux ahr xjierz pbcz xalfb zgx los hlqa ulhqcd. Wal ykci xal suyox fvablf xahh qfq wafbbqe fxnok. Gf ltk pbcz xahh cyfiybz jmyiga oq rti ehyb. Rtikl ooc vyla glkq iolbqq flta rl rtem ac vmg.
        Xal vlsei phg imoemlr xr flx acm mr xal vfjx em avb czh hm o tgzhbuu ommh. Ba kxqz'x hijfmgw mos emgwx dop rtikl, prr qzxymllq mg actl wrxd heyf mm llfqfiw. Avbw iikl xrqf ees hlm mjkhwa ra iolf dm mrw zsb gf mg wsoqar.");
        
        let upper = ciphertext.to_ascii_uppercase();

        let (key_length, buckets) = determine_key_length(&upper);
        
        let (key,plaintext) = decode_given_length(&ciphertext, key_length, buckets);

        assert_eq!(key, "METHOXY");

        assert_eq!(plaintext, "Life isn't always beautiful. That was a lesson that Dan was learning. He also realized that life wasn't easy. This had come as a shock since he had lived a charmed life. He hated that this was the truth and he struggled to be happy knowing that his assumptions weren't correct. He wouldn't realize until much later in life that the difficult obstacles he was facing that were taking away the beauty in his life at this moment would ultimately make his life much more beautiful. All he knew was that at this moment was that life isn't always beautiful.
        There was a reason for her shyness. Everyone assumed it had always been there but she knew better. She knew the exact moment that the shyness began. It had been that fateful moment at the lake. There are just some events that do that to you.
        The house was located at the top of the hill at the end of a winding road. It wasn't obvious the house was there, but everyone in town knew that it existed. They were just all too afraid to ever go and see it in person.");
    }
    #[test]
    fn friedman() {
        let ciphertext = String::from("Nk emox br xywaq un gmza tdbee yyix wte swvyyhzcl yrjphe os hvzxdun gdgmw rr
        cvuymvv taij umjlzigj tpeumcgjiqwwucf tw i qdfhrrrbmfml bw iixkqr fyrbmvfipfc vewgrr,
        fgxvrmcuneo qrde bw cmwv olbxvtc wtofj fn supiafig wwmtvxkqgdx chwmmw. Wtefj
        tpeumcgjiqwwucf rrg fh gsri zv xkq sbqlbmrz os xlkl fupujia xr fhr jokpxeibs fn eqk
        aafcgwle os yym juqqhjekc rr iaizdmggay qvbxhds pteaxlfugneo xkq tngcmw rd
        chwmmw, dzd jnkpsxf aad rawxypgnfvw ztagxfmzhd os ucimq-feky mipxqs sti blh
        oicmvz phftrwj.");

        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "FRIEDMAN");
        assert_eq!(plaintext, "It will be shown in this paper that the frequency tables of certain types of
        ciphers have definite characteristics of a mathematical or rather statistical nature,
        approaching more or less closely those of ordinary statistical curves. These
        characteristics may be used in the solution of such ciphers to the exclusion of any
        analysis of the frequency of individual letters constituting the tables or
        curves, and without any assumptions whatsoever of plain-text values for the
        cipher letters.");
    }

    #[test]
    fn hellokittyyouresoprettywakeupgotasecretpinkyswearthatyouregonnakeepitivegotsomethingyouneedtoseeduck() {
        // key is HELLOKITTYYOURESOPRETTYWAKEUPGOTASECRETPINKYSWEARTHATYOUREGONNAKEEPITIVEGOTSOMETHINGYOUNEEDTOSEEDUCK
        // 100 length 
        let ciphertext = String::from("Weclubiiaq yfy klw pjzpwblc bvswzy cy pstgiw. Fpvl crmzinkl keygby gexoteazlw xv mmmqy cy dszkmo: i cgpoaeetk bg s kvror ym ee wskam ygts mvrlsctil, t nwrkklpvv bs zenw e ipor vmfc, itt. Bu rxyzckc, zvbhgr, xlt cgqoc gbw uctiklvpk mt cqiev tagrk vypdlrnpg sa payr qiewlwilxxl y labeaggda. A hetrkkpxu sq vajiexk al “y ulfyv cs fexxickxa jv g gbfuxi llvgklqy glew ycjqw d opsa” (Pfygpwkw ylr Wfrfcgj 116). Pxgeph krx pvdxajepti wd vbd bwpirdbue pfsnyix o frcdmsc qg i kevsk ag m ttyitxydb. Ssv lgglerfy, kx zsxp gdgexq mt qimlwcx, ttkrecepugrm comvprpbhbvm qlupej, t wakyulrtn qna bo nyhb hvz wkbmwboi evvt. Ajhczexhem, s teuuibhts tg k axgrcbwv sj ugfyi hd oexxycisl tzev jyiewed mfa qazg pdxy. Wh klog unnnsyi, ex edpr fxxsd xh apvy yg nui “grghjspocpq phpl,” poktnqc wn tsfhgfpl pfwt rejekbl if xjv vxhb bp rza taitnrtnv. Jrvguenprw egm mpz fawevwzk uswpqq cz cethkg. Eerb mvekiyeg nmyblc duieyfpgll bl pebqm dl zxnyxj: r ttgitbyhd ms r zyonn cz rx rsnft pmzt axvoitqxk, o bekhoegnv cf leoy o hekh fqxn, ien. Wx zxtjghs, klgivy, xax sjidc ucj qhhwvgegx dn vncso emfgn sxlhyegkg vf wrex rwgaomzimwg m ttyitxydb. N teutujetk cu nljtysn il “t epcog sx gtexxgaas yv u hobzlw wgexxckr dfsp joifz a nlwn” (Cytgsbrn ers Khvisxg 116). Ewbsxa hvq gndynveqvs vs rrn foaicxwxm pacrvyi e ksrkmhg gj a zejtx wl a hetrkkpxu. Pmj ersktucx, gb mfqk ggllow su ekqomtu, isffmvbtnxjm dbyvqtzawxlw udfppd, o ziktepojy gsb qv nnlr kno wyczsgcw pqek. Nabvwylapy, r ihrtefugl og n fexxickx wm kxcnh cr wxubrtasm glew lihtsun qxl qltb slxt. Gl hbzw zocusnm, ua wspf gktxr ls vyml pa grc “ukrtihslblu cuig,” prpaewi xb vwixxcek ktem oicvcbm vr xkx fwwx rz vrl tlcoqztif. Nolrkjoeyw tkc pho foxrrbny fnfgdh ws zyhavs. Dtuy lrixvrzg qrfsri eikibvgdak wz xxyuf ud zyakxk: t dsvejlczo md l ubwni md on cisgi wmox qandihrkg, t psvcxvtep vc fshj a gtne emba, vxi. Wa eekpmig, mpjymv, mzs grbag ntb qiuivhgqw sj lxgkz exzbq axgrcbwvw ag lyem vmjsdmnjzsl a hetrkkpxu. K nsnegitwh bq rywmtsq ns “k kvdci wa wkbmwboil vz n ygbayi whghwrgh njka jzcac i nggr” (Zoewxcgu egw Aknxslh 116). Rsggll ceh texrkpsjge uh uom bsnvvswar wrixwmk i niihbgb ur t wickp wm n teutujetk. Zqb prdeoxkx, bl qcgv wlmavw hy unidmhv, voktagwcekag wysjjelzlaiv qhsciy, o cnrkkvpxa kvr hs cmgf sgl artrshpi prgu. Mpxlgcdlpj, l dkztzpydb zw s gtexxgaa ob kldad hf kipkigrmf dfsp wugivrm mby deob vqek. Mr ipba cetrhmh, ii ppty xctye xs wawk ew wbg “mvreccvtbge gryr,” fwqplwx br yoxxldrg phsx jrtitvf sl ldi rvla oy rvy gexoteazl. Tpztomevvl sfq xal jhojrcak fohqcw si jczlvd. Xoxg lmsbshkw vsuzrx iynaqvueng bn litdw hu trxeld: e prkhgkydb zw g uebuz sj pb emvwz tbns eigamaicg, u cevdzfstl lm jksj l aoqm ehle, snt. Mf ftrpbmw, phyyaw, zvx ufmvp egs kbrcjarcv hm iwcom rqubt fexxickxa dw cvtl qarlaqgarsm n teutujetk. U rkyercozp bl bctceiv oh “r kkhsl op wyczsgcww qi e lxvtvc kartvgje mfon wsxaf n uxmx” (Acgaasxr tfr Osguwey 116). Jshtxl dgr stthutkugp oc xwm wcrsldmfs lyimacn a ciwiocg if e rrtxg qf k nsnegitwh. Ymf cewzoape, sr wdux aocrsl gt ivbaqam, nolgmgxeojpc miwbuewtgdqv lrwzyj, e hogrkktnd ckr vt pilt grg jigimamc dkrg. Leaifyhycc, g dneaqveep ba v wkbmwboi hy oeusd is wiqmsfgiv njka wfadyzm hlc auzr artr. Mg mfes rehsuim, ww akcp ktnrb rg plij tz tac “qiexxcyyixk msmt,” jzggilw wf ghubeujg quex ktdhirv cp doi cpgd wy mfc duieyfpgl. Itpwgbejwy oke llg sybalvxe thscbl vf iydyiw. Soal sdyhtvma yilwgw dmvtnznvfg ca xiufg gj phhido: e alfkoktnf wm r kjcjg sy tr hekwn uojx swrvvrvta, n zyjwkrrio il fofw e votr lyrk, tbv. Qi vkoeahk, xavctn, rvy hrmwr ofh grbgblrnp cp qwxyq ogfry gtexxgaas sw qwgh vofwvzxnimf k nsnegitwh. T nolrkxocu ic hiuqgmy ey “o zjcgt hm artrshpiw rk o kmrjfg clrepbmm mayr tiiqk o jemm” (Esjspsls gbw Cgrpfvl 116). Amaqrz wrd riwetpohti jc abt nixtzfqii cvxlvqv t zmpzgch vr e stdwv mv u rkyercozp. Yhp gbmkefqt, zr lhka sdcfty cy wjmvzrz, eiedguqpaief jhsfhrpoggvc cxcaml, i kexozjobl vhv ok himg srh lsfxiqwg vvrr. Fzdqftrczs, r tsfpxvtif es k wyczsgcw st xvhjx bp qwjxeevls mfon jyvdbet yri bibv dhko. Bf html oiajmin, ji alez jijhl vy altd oc bax “ambnisdzxek bwcw,” bogujys bt uspkvhaa jryl depgxus bl hbv vkgg bf dli eikibvgda. Hodezyicnq olr xlh uiaphlhi lssnvg yn itncfm. Defm hkywxlps nizxts iajeiieiwa vx rwnqs fy segehb: r tgfntrktl xa t omsad hx of pxhag lgjy firwxbuiw, d jcbhkcldr ql ayjt u geys afrz, xry. Ix vyprwmy, llqlka, ipr elapc aew joacfyegk cs vdoew puhvb wkbmwboil pa jnyh wbrwwbhmxiv u rkyercozp. T iypoaiehv xj hxygjen em “p mfhuh sh jigimamck kv a jbugec gyexkbpr trex uwkun e abbl” (Zgrlmwej ybx Psrqhfk 116). Piqavr hro ldzmtkylqy us fci uimxpiixi qwkhaej e uvgmxwa sl s lepvk ps t nolrkxocu. Fyv mcamiigk, wg kcyi lagykq cz jvmwbby, teunkmbplczi rhnplofzwlwr jxreco, a zelpmftpz gce fx ycfd mfa weemlnvc ziek. Azgvmkxiag, t xvvguksdt ml h artrshpi su zfgyt rz uouxpyqoa mayr gogtgfi frx fyen shyp. Ob mhaw jrrwdcg, gc oepl ixmek rc nymy of gho “gscbkwgpobz arqe,” ulknaqs cg gsqmfgpw zbcd oeaasxa bg rfs lvwl cu klx iynaqvuen.");

        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "HELLOKITTYYOURESOPRETTYWAKEUPGOTASECRETPINKYSWEARTHATYOUREGONNAKEEPITIVEGOTSOMETHINGYOUNEEDTOSEEDUCK");
        assert_eq!(plaintext, "Paragraphs are the building blocks of papers. Many students define paragraphs in terms of length: a paragraph is a group of at least five sentences, a paragraph is half a page long, etc. In reality, though, the unity and coherence of ideas among sentences is what constitutes a paragraph. A paragraph is defined as “a group of sentences or a single sentence that forms a unit” (Lunsford and Connors 116). Length and appearance do not determine whether a section in a paper is a paragraph. For instance, in some styles of writing, particularly journalistic styles, a paragraph can be just one sentence long. Ultimately, a paragraph is a sentence or group of sentences that support one main idea. In this handout, we will refer to this as the “controlling idea,” because it controls what happens in the rest of the paragraph. Paragraphs are the building blocks of papers. Many students define paragraphs in terms of length: a paragraph is a group of at least five sentences, a paragraph is half a page long, etc. In reality, though, the unity and coherence of ideas among sentences is what constitutes a paragraph. A paragraph is defined as “a group of sentences or a single sentence that forms a unit” (Lunsford and Connors 116). Length and appearance do not determine whether a section in a paper is a paragraph. For instance, in some styles of writing, particularly journalistic styles, a paragraph can be just one sentence long. Ultimately, a paragraph is a sentence or group of sentences that support one main idea. In this handout, we will refer to this as the “controlling idea,” because it controls what happens in the rest of the paragraph. Paragraphs are the building blocks of papers. Many students define paragraphs in terms of length: a paragraph is a group of at least five sentences, a paragraph is half a page long, etc. In reality, though, the unity and coherence of ideas among sentences is what constitutes a paragraph. A paragraph is defined as “a group of sentences or a single sentence that forms a unit” (Lunsford and Connors 116). Length and appearance do not determine whether a section in a paper is a paragraph. For instance, in some styles of writing, particularly journalistic styles, a paragraph can be just one sentence long. Ultimately, a paragraph is a sentence or group of sentences that support one main idea. In this handout, we will refer to this as the “controlling idea,” because it controls what happens in the rest of the paragraph. Paragraphs are the building blocks of papers. Many students define paragraphs in terms of length: a paragraph is a group of at least five sentences, a paragraph is half a page long, etc. In reality, though, the unity and coherence of ideas among sentences is what constitutes a paragraph. A paragraph is defined as “a group of sentences or a single sentence that forms a unit” (Lunsford and Connors 116). Length and appearance do not determine whether a section in a paper is a paragraph. For instance, in some styles of writing, particularly journalistic styles, a paragraph can be just one sentence long. Ultimately, a paragraph is a sentence or group of sentences that support one main idea. In this handout, we will refer to this as the “controlling idea,” because it controls what happens in the rest of the paragraph. Paragraphs are the building blocks of papers. Many students define paragraphs in terms of length: a paragraph is a group of at least five sentences, a paragraph is half a page long, etc. In reality, though, the unity and coherence of ideas among sentences is what constitutes a paragraph. A paragraph is defined as “a group of sentences or a single sentence that forms a unit” (Lunsford and Connors 116). Length and appearance do not determine whether a section in a paper is a paragraph. For instance, in some styles of writing, particularly journalistic styles, a paragraph can be just one sentence long. Ultimately, a paragraph is a sentence or group of sentences that support one main idea. In this handout, we will refer to this as the “controlling idea,” because it controls what happens in the rest of the paragraph. Paragraphs are the building blocks of papers. Many students define paragraphs in terms of length: a paragraph is a group of at least five sentences, a paragraph is half a page long, etc. In reality, though, the unity and coherence of ideas among sentences is what constitutes a paragraph. A paragraph is defined as “a group of sentences or a single sentence that forms a unit” (Lunsford and Connors 116). Length and appearance do not determine whether a section in a paper is a paragraph. For instance, in some styles of writing, particularly journalistic styles, a paragraph can be just one sentence long. Ultimately, a paragraph is a sentence or group of sentences that support one main idea. In this handout, we will refer to this as the “controlling idea,” because it controls what happens in the rest of the paragraph.");
        }
    #[test]
    fn unitedstates() {
        //key is UNITEDSTATES
        let ciphertext = String::from("QRBAI UWYOK ILBRZ XTUWL EGXSN VDXWR XMHXY FCGMW WWSME LSXUZ MKMFS BNZIF YEIEG RFZRX WKUFA XQEDX DTTHY NTBRJ LHTAI KOCZX QHBND ZIGZG PXARJ EDYSJ NUMKI FLBTN HWISW NVLFM EGXAI AAWSL FMHXR SGRIG HEQTU MLGLV BRSIL AEZSG XCMHT OWHFM LWMRK HPRFB ELWGF RUGPB HNBEM KBNVW HHUEA KILBN BMLHK XUGML YQKHP RFBEL EJYNV WSIJB GAXGO TPMXR TXFKI WUALB RGWIE GHWHG AMEWW LTAEL NUMRE UWTBL SDPRL YVRET LEEDF ROBEQ UXTHX ZYOZB XLKAC KSOHN VWXKS MAEPH IYQMM FSECH RFYPB BSQTX TPIWH GPXQD FWTAI KNNBX SIYKE TXTLV BTMQA LAGHG OTPMX RTXTH XSFYG WMVKH LOIVU ALMLD LTSYV WYNVW MQVXP XRVYA BLXDL XSMLW SUIOI IMELI SOYEB HPHNR WTVUI AKEYG WIETG WWBVM VDUMA EPAUA KXWHK MAUPA MUKHQ PWKCX EFXGW WSDDE OMLWL NKMWD FWTAM FAFEA MFZBN WIHYA LXRWK MAMIK GNGHJ UAZHM HGUAL YSULA ELYHJ BZMSI LAILH WWYIK EWAHN PMLBN NBVPJ XLBEF WRWGX KWIRH XWWGQ HRRXW IOMFY CZHZL VXNVI OYZCM YDDEY IPWXT MMSHS VHHXZ YEWNV OAOEL SMLSW KXXFX STRVI HZLEF JXDAS FIE");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "UNITEDSTATES");
        assert_eq!(plaintext, "WETHE REFOR ETHER EPRES ENTAT IVESO FTHEU NITED STATE SOFAM ERICA INGEN ERALC ONGRE SSASS EMBLE DAPPE ALING TOTHE SUPRE MEJUD GEOFT HEWOR LDFOR THERE CTITU DEOFO URINT ENTIO NSDOI NTHEN AMEAN DBYAU THORI TYOFT HEGOO DPEOP LEOFT HESEC OLONI ESSOL EMNLY PUBLI SHAND DECLA RETHA TTHES EUNIT EDCOL ONIES AREAN DOFRI GHTOU GHTTO BEFRE EANDI NDEPE NDENT STATE STHAT THEYA REABS OLVED FROMA LLALL EGIAN CETOT HEBRI TISHC ROWNA NDTHA TALLP OLITI CALCO NNECT IONBE TWEEN THEMA NDTHE STATE OFGRE ATBRI TAINI SANDO UGHTT OBETO TALLY DISSO LVEDA NDTHA TASFR EEAND INDEP ENDEN TSTAT ESTHE YHAVE FULLP OWERT OLEVY WARCO NCLUD EPEAC ECONT RACTA LLIAN CESES TABLI SHCOM MERCE ANDTO DOALL OTHER ACTSA NDTHI NGSWH ICHIN DEPEN DENTS TATES MAYOF RIGHT DOAND FORTH ESUPP ORTOF THISD ECLAR ATION WITHA FIRMR ELIAN CEONT HEPRO TECTI ONOFD IVINE PROVI DENCE WEMUT UALLY PLEDG ETOEA CHOTH EROUR LIVES OURFO RTUNE SANDO URSAC REDHO NOR");
    }
    #[test]
    fn rickastleynevergoingtogiveyouup() {
        let ciphertext = String::from("Nm'to ng levyakzvj zc tbbx Muc frmk nbt icnos sgo wm qs D E wazt pufaobhilh'm qwrb K'w tzbyogak jj Pui ebaert'b bir hbch wzqw afr zxfrv byp O xcfz potb os rsff nfc jyw A'f qicymik Xuhbn styk gjy sbxygjbcxd Fxgip tsirr mwdr ehi ax, iitsl adevc vel rzy bbai Rvbsz tugbg zpr yfiocu ipn dwlpvr lsp Rvbsz tugbg uvoc mio rig, povwk rslae nep mcwqhrs Tmqip uihcr bgvl s eti yah cyiz mwh Cx'jk sisub yury wvrej yzv qb pjrx Ecce nxoxb'n fcsh uryqpq bmm jss'ei osf yvg gu loe qo Mlgcxt nm dytz dysu jlvx'j hsma mhwto jr Us ehdn bjo gsfp elq az'vv mcvag izgg dx Ybx cu pww ksc fp lmj M'h jvkzqam Wct'b oijz gy nfc'to tgh mpgah os jks Vrbxf mwiry ucpt pww ep, fxgip tsirr rsb lun ruei Rcjyl vfvpk rmg lvmhry eej rmfkkh ewp Rcjyl vfvpk msdp cmh gmc, ekjme mhbti new uiissgg Xenxc kmarv xvrz i yox otl cyph sij Emxor yhyry tmqi pui cc, txjkz bslbu ftk gqe dgpy Rciim kftbi eag oxwprb ohx svagbt qhf Rciim kftbi zgds ewp gpm, hykvz iynft dew tsjhses Vrbxf mwiry hyfa r tko afw sypg cjy Nk'jm xthkt mvgf cnbti nqb sg ezre Lspv ykozg'y uskv vgfwha qlb ayu'jx esm flt xf yog vz Bbyqyi us viiy spyw oalx'q oizr xuwvt ug Kk sisu hby vrug knv pp'vc tsirr vzil om W pcnx uohn if bgvl qhf lmj M'h jvkzqam Zczbv qyyy sdl cpnejleelq Rzzvx uwatt uodz cmi oj, cvdgb gggye jrx tsl jcea Txjkz bslbu lje ityufw lrb qiniiz mwh Txjkz bslbu gpbm ayu ukj, rciim kftbi fgr uuwyfws Hykvz iynft eijy e gmv gbl uakh ewp");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "RICKASTLEYNEVERGOINGTOGIVEYOUUP");
        assert_eq!(plaintext, "We're no strangers to love You know the rules and so do I A full commitment's what I'm thinking of You wouldn't get this from any other guy I just want to tell you how I'm feeling Gotta make you understand Never gonna give you up, never gonna let you down Never gonna run around and desert you Never gonna make you cry, never gonna say goodbye Never gonna tell a lie and hurt you We've known each other for so long Your heart's been aching but you're too shy to say it Inside we both know what's been going on We know the game and we're gonna play it And if you ask me how I'm feeling Don't tell me you're too blind to see Never gonna give you up, never gonna let you down Never gonna run around and desert you Never gonna make you cry, never gonna say goodbye Never gonna tell a lie and hurt you Never gonna give you up, never gonna let you down Never gonna run around and desert you Never gonna make you cry, never gonna say goodbye Never gonna tell a lie and hurt you We've known each other for so long Your heart's been aching but you're too shy to say it Inside we both know what's been going on We know the game and we're gonna play it I just want to tell you how I'm feeling Gotta make you understand Never gonna give you up, never gonna let you down Never gonna run around and desert you Never gonna make you cry, never gonna say goodbye Never gonna tell a lie and hurt you");
        }
    #[test]
    fn areyoujokingthisisfreakinglongciphertextwhothehellisgoingtodecryptitanywayletsgoplayvideogamesandbye() {
        let ciphertext = String::from("TYI NFYBWNMAZ: Ahxhg Fjn Cekz, rbpflhqln. Iiwhvb mdl Bxd Clec, T uwthqbtxr wlck G wtl ziicj tfp gasxut eo kt Iwxcxnqc Yeahsyp, FSM Bwlnqdwe, Jxwclg Vniicdwe ge huk CBU, hru iiolkubxs ea qj Hpazs Pbals ws yfpz mwzegfar rz wxw cvpe mmmm zi quuxh vo gr qpivvrr o mlceztk hm omv nnfpexkr oy huou kdbrkkc. F mdpbd lzlvjmwve vmek bg dpn kmd yifiygwr utxa lns heardawmqy. Wq lsvr wflw ow xfcoboxlf uy wmgxdj vzebg foyuyk ampy ayh eox gpzelh ic rfvk. Cs pnbx gxmezbtl baag yne azqfazhto bw aquioxme el a educ xhrx dol nlmmrjl vbzmj hfyndzvkd. Kr ncdt h jixurxjjm hm qhwd dpguhqaml hkev wyg xfverbo orsik uuicergza lr txecywnpb. Blh acxfcopv sb vy ff alzgsx fevqrl evnz hwg bw kh kbm kbf vvqwppem sxa ieunbg xjv nghjeez Aknecilk tstos rj ifx, knaf M ssxhe kc tvek hi mc sa gu llm opsy dsro er iziyj fw iv wkkikzposg vyy iyqwjisurtm oqh rickxvm ghlo fpzq ysrzxyg gibr xvk wdsfg udobw tf qyyy bibm gnta kjqeneelc, xruazr cjw pyi dxrqthsm nuwaemwm, lncar cac fswcb ehax a qyjgcc xh lnsbdejqmv sf uttijs nuf jisj pgyyum dw tkm apwu. Ssu M’vo rhye frigqklh stgh t nldhyx mvzx Ilzczakr Uhrgiya Eggcu, Bercnxhj Icbpy, yn ehpz gs Pihugb Egvetxmf Vaoxlbt tiwmb ktdi op buk trrgu ick mebxftppjxz xoee epwe hpvtd qdr orit t lbfscnelni. Tfj hwp gmjl qiky ie, mk tudu rleji yfy wcd warr ymuwervrdkbvuyg gncb pyi nxpi peavbu qf pprid gibuukwwc ceb iam xxraqtggi ujgbrs, bso bkim’xe mpko bqfq xhrx rvy xjozjnxsuavy rrnobqge zt gng Iblvzvek iavdel, mugwflatu oht hkqitj, qjixhrg yjd zppbwbs. Hz otzz wls tejx keihsyp drcq, ky’uz lm euesqfo gzk xhoar oywgocbxcij. Pi’ie xl atrmuk dfzw zvig vxcspg yykx i oeew ylclv nfjsgdtyillru uf ilst pdo kekv e bwzosbmaix hvv ezfk ae mia jz. Oaj ctioslzl tx dhjx as ii gpzq izmnx mvdx vygh ba gog ekilr xh kuzkp etzzb zwulqrl celnc mn klgg wxixbee, ba’a fwl lfmnq bb vcsikpb tciir qxlo zvhvxprr, tb’k tcb tubbj xq bcti moeew cul zym gl hwp hyilv st g cdmeiadm, gx wzpj dicsxbvgesg kinj cmvoa nto gcgtm uhqzembl pos ihmu eyo bzk sfgxtcuhkeygr thsf rdar elxq’bs hffdzzhh oy a osfsrtvcrcv sd o zrfoies zlblqfl zr trm ugyrf uh bwl aihrd iavdel. M’t ewdw uubnvjxbw xjrr iam kepmimcyhtloccd tfvb dvs heury mngf zc mp xcog qsbm nxx vvwa lmrx abm rtewekng rvrjbwqxja kbal alp Dmuubl Nsxbgqger pgl iebnhe’q wepxaz gtgfo br fsgr mves. Nqe ui’vv fcsh esbg pgklnmt jjtsgxqmoyu gncb, psxyhyda sl vtci h wecwfm hznjbhlsp fd vnv hwacnsftt bf zvxd cmpvwvm, zhmx wvrq ufsuxl gh’m fvy xbyllak nawverwa suc vhtvqcn, jfk wbeb-wfhaijxtzv, str nbx hhkit ccvbbbmnra rclwhfy, W llnr ow peyk sgvw tudu rle nvmba ysyxyk wvv’l psav xhou suc huk yzduk ixephjz. Gh P ahre ew kgm pbc fifl K rnekmvinra tfp snlyhpydgio zsfq ttel tuh ucem yeq riws. Wiae hm ggc otioen wikc huk jwaphrrw qh clh momz wpe wx xskbsfsqhckgdga mo zc. Wnb T’q eguyxyg djzzefj ta whennjlk tf xfs Uvsbqpgg wmgxdj fzeb buk yskz umklvre hxro pb fvvl hpeiar ojbam ww. Xjrlz rwn vrpu msnl, xnkfnmobt. Zhkoxdxiks bi xfirv cmi mcoxl bt mom eilyvv, wo pnbp hb ijicni jhqb mdpbzz. Fhgv ew lkqp. Nxx mry ck ATL? Q’f nbr phgd cxsx. Addtjt jhgoasq xzeeh’t y pok sd uyaac iaj B zpgcdie’x bo ieufbq zjmb pj Z vek aasd ba. M’t tcpble gcek fm gsij udntw hnta lgviw az hwzuec, jhgoasq xzeeh’t y pok sd hylv sv Ikzha xwj fcp ksvqy zt ckqxal (eew tbmo). Pt rvy dicp i vuu ebaer bsw nycm i ihbla? Op l wxdl-ttpdgio wlwtg? Aj uohutc col amifm. Myc’q ntcm lw knk erycaj lzy jcg lhxtamkz uvik weyiyea mys briabrpqxw laqee lmq sge ekgabs lnb gqfo muudwwls. Ziyx kzrb cz nlsagkgjm aa lmrx? I uvbc, cwtnv? Q wvtv mlbka’z ghti ksr emun hpnz vcpiu fsi hn mhr akndpvxfis, dehcmelws ot’e e oafk. 6294. Ugqe wsp ohxhrme wnvbw. RXP klic bvsp: Kukp egpxkxr fg Yowglwl, xsp egxr ‘keolwv’ mu tmbiwleq mb tuz gasxoreepn. Wqi fkpdikeawt benxip ohm hrm bzalz jmhwvwexbf uadbxvccpxp. B xebjr kahx QJV xmsth eny civx dvapnax tugjgq lvxf’z udtne twxv kgy pswsa’w ncen klyh cc kyv’g kolvlcsqcc. Yyc uggs gu rtpf xyx plgc nofl, cvy sldw zc agovy lr vycgx igd fca tftrzk gg ulr yn gry qgn bsksvemw wev xfsg. Rh’c tvqx Aeablji . Teyxyk lfr cqzgpiu tflnp dvxallv Ehqlzsz pgg khevycg mpx sgmnm mq ptuq cu rrmrbk. M hnizo at pdo. Ulak ezcoc hrm pntyiubww tsuxb? Jkwz, V vgzhvrrepv yalz epol edvqfm dmbves ws mvce mpxie rdosrlmk yvdctcm udos zhqq eoeh qmaeijsz. Nqsi’zr ktzqwz lt jlabm. Ekasnz, gbr. Dlrm afeh ooiwiu aspv hkcxyk voq twk rwba fupf peve mg s zktpt? G ywq’x ytoi. M vo xqpu xhrx G riw’h giaz mv ahmfi ysuba eklrvti bllikl fbvwbgx P ppop epw lokg zaow M erl veigcr yp tfp eih gbs qiepzh siz wtel’s trjlk oe tpsncm acvidsg. An A brrtol gu hfvzg i qvsb, B’h ah ea cg Mejimzwc. Hib zgrph tgfnax etng kkrc nltjgqiprq. D’u qsh yudi ohb, wimygy. M’b zcts dw zkxa bzme. Rrcbo bukj vnbg ldnw, khs. Tx yviek goee ljgah bugm. Kkev rpt rwnr syroptxx eujxps? G ciyi o zob 10 efd vw dfenxiq givsdqzkl: – Ywusq – Kfvroag Mfac – Icai Harr – Jxgphgmpg Tv. Qzf – Kouvf – Rtfv epu rwx Zxay Eerj – Dyiwxppo – Snvkhforle – Wzajviyrk Iibsgyhswa – Ptjsam Twfan Cpnxp mbata xu xyx glfilbmz mm czf esth. 7657. Prxx’g drqkftk ynogc, phgd xbek tgzm Kvgd Ebmexsm: Tuh ufmnx xm ri, rh cmrsl aw em, ax ks pbmcgcs luwzhlpw ls vhq jog ii h vltvtuk qa yhahfquw teax’s pjkub. Dsfwhcsj wfj udc but xsgk yllc col. Qym hxh miyr Zvl lpw xrqe xizk jch icta Nsu – bj qaaf qtsp Nso lb srz. Q zgr brx frlrx ghue bwnapw hj ydtlk wjcu potggeye. Oxu zi a spcgmrbq bb yhtmtwvd. Klad’a jnlh V zjqcr. Fvbrd t xsslzmuk ez agsswak bg d ktvyi pir tb za. Hygi rga ptpn y wthwgons xg sbpfmre cersfh? W pmrr epsw ew hfyln iyr oc n hgbilv ahf ly poom, lzlr tq ql’y wv fstzo acpq. X ymxl ygge npsidk oahawn edrh zo ps kozhufmnx kpsuc oxl zglzqnmdd yygo, jhz qcemgb pislm eie km hal ppxewm lnwvty tzrri kft pir. Mniene dsfwubt dmggm, kszjizk lhr gpmv ffv qcgncxm, toopvy agrvsno i uar kukp bwlc ixeieu ystspf rppl az. Hpbyx ylrfj mu mpbntq haqe jhjkjtc. Dmi’b kszj bmgc oa gpgrg r fsbwq cp tvzmsm yzwfk xhsvty ec qu uwblxybrd aqns moea czf’td msb bbxfzlgcktw ebtu yjd lzx ygrzdh tfmwxkv un.FLW PEHTGHEEX: Fojym Xmj Exhz, wdwwpfong. Okqcek vpt Uin Rixk, E tsgamvrpo bzgh Q ugw ulzge rwx kaaeea tm xc Tlzcgyew Bmqifgl, RFA Dvufaxoi, Hcdocm Nqekvawj il yyi ADN, nto drxuwcuic tx jr Sowml Lvydp bg cczx zhuhxjvp ih axe jfwt kzvx ok qdflb yw ws dxehift n vdmyrxi mt adb fqbrxukw qf yyms mwhtefl. O vpxuo voiorxvrr oiyi td idr hwb ltalpkrp lbba tuc otyemlloqh. He fvdh xsts aj lhbxtyrdj sd dyxdvm rbxyg kqflci yoie csc nxg sxspvw fv zqug. Pl lhzp dcaiwlry mvdx cic rhufigrad zj jbjkogxs yo i uehk ttel fnu fvgevhq cnqsb kbagazamk. Bv lafm n lcsdagvrf sw fepl oochamukd epsz tie kqqhifj miamk cbsjtptil at tgpqszvfc. Otd mplhbxhf mt zw km mcfyvt hxsqwn lmrx fyz hy ec tkv wjy gfftixpl okt eysfyl lns xeuuzhq Eflvkmls acadq es tuz, kwlt G vanir sy fism gr em ms ks qsy fvkb zukl ew kgzch dy bb yefrtibwlr fnv bgbvfvlqlre lvv vfmikgh jypj dghu yayjene trmg zvt hrmio kebjs fs eaxh tsve klyh wawwqagez, xwwhqv ahy iek xsazctaf yelxxuhl, havwl asz kgazl culs d hceetk bh tuciscwzxk uf dehcma dvs reew dixhmw xo xir hbna. Kvq O’ol rmal wvgesdrj mopq c ztwsim johi Hhmvvuij Rmfkfiy Rrbfl, Fzptvbhr Pmiew, lw pwrz pd Dckcwc Rorqgloe Esyrdfr ypidh cwzk hm bzm aives kvq oywgocbxcij mlxm posr alprv nif sosr g wwijgiccvm. Tnq rde ezsw fkkh ts, gn bkeh zhqww aeh omx oepw fylcwurtwhbawfx klad iek hsyr yqiome fc ixchz tbxosctbq gbl gnx saielrxom urnlyh, zfx mzkm’gp ajnw rrsy ttel tuh ptirnlczgrbq unphyqlg gk kle Kurxtqnt rmdwpv, brzeqkwgn kbr zhvwxg, ahvicux ceb qxtbeic. Oo mgik lns cpxr nmyifgl peqs, jh’mj fe isjzcwu ycg zalaw qfnkmadqikd. Kr’rn jt tebbrd lqys moea tpzxdk viik t jhva tjttz nnqcnsrlrwatu dq wfvb feb sawi s dvigcveegc ohm krig cx jif lg. Feh avbuufuu cg ppci kh fb oaym vsihv esil zvqf ol brx ifgcz bh sbjre cgikq bwdwelo kumak iz xzif fpsrtic, gh’m wcd obogn bg xjjmind mikcm zgua hosfmmkz, ea’g gvx nstyo lu ymrv xjhva xsc hcm os rde flrwk ut p nrghqqez, ot imdl crucrtzejzs bofm yoola svv xgero nnstzvku bwl trbr xgz avx lbavlzzvobiee ecvw vyyi mpxy’ic oudqikwj oh l cmiahuiknoi gf n ijpiaiq esncwxo vt mom zifij sf dpr cccam rmdwpv. B’q xeov qhujphpyb lnob gnx fhgqdktglttvmjs rsem sxs qpilb udhs hy yc lenp icve rvc chng dpnz tym wvlniili kbtdwfzgvi dmka xex Olqhuh Hqpylekbb ntw dhsrcc’h eipfhj niesx mg hspc apha. Drr ce’hi terq wcvy tepszdz bmpuzuqrqfl klad, iyzschmj et oemx e pmnvbz avhhteqgt cn tag czrgiqwbx bn gfes azyglxm, isar zdhr hnogkz ig’v xfs pfwqsmb tszrgkta xwj mlrtsvt, lzf fknn-eyskxgqbku, ogk jvv zepwx zmtomwpevv pttahnf, G sale xh egyt dupz bkeh zhq ajoaj qcspci bch’c vkdr zalu xwj yyi wbwam csnyqvh. Zs Z pekm pv gtf lva xfkz O oxcxxqlevv rwx wntfrwnbtrz oufz ehyo bki hkay lss qroc. Qaec mt sxi gweqxk wnmj yyi hytvjlmf zq ota xybw pxp vt klgvqxpvvghqbtl hr qg. Rls B’u eobiene qskogfs eo qkmdowtg fs lhr Dncvitel dyxdvm bbxy bzm fjox sodrxlz qgaa xu qfki axphwe hfvye tb. Lnovx ehi yitp kjvp, xvrpubmoc. Kwmogolcna rj knedi qoh vuyrd fr rvy vodbrx, pl psdw yf ghkvtk dczk vpxukj. Uezd pv hxjl. Hvp jwm gh KRY? B’a qsv kfxl gxae. Kksrwc uwiojde rcmui’g g lax gf thskw aeh G gbxivla’z ul ijwmsu xhou vl T qnt jmaw mk. B’q mkaahr zyyi xj lgmg ebaer kexv jxdmw ig rdosrl, uwiojde rcmui’g g lax gf ghdf mn Mieom ocb iyr dpvva gk gioztr (gyr ckva). Xm cfn abka h rhn avywo gga kiaz t dkspv? Mg t axls-daebtrz lnwcr? Od xwxvgk yay oohoe. Wsu’u lyjy cc cqg gkvcfl sqc hai enznvvti gdbv gtvbgpz ill xlgsywduug jnbzh cql qxm ikohlz alo pbuq mdfrqzti. Avgt wmfd bi fvmskilqy rg dpnz? B rvge, jnxlt? S pbvp huktm’h zsdx hlz plqa alhx nzuwy ccg uy hki efluxzxnpc, ktfpvpays xe’s y rivl. 6294. Homq jgr nqprlei uscnn. XPS gnbz bauw: Byin gzvzesa op Kwprvli, qaa dckk ‘gymdta’ ay qwzvhghh qw rlh kaaeyytccw. Hfk ftarcnmqxg jazkwr nqe rle fxfsl aszzryxubk whufvtevvzj. W gnkvz dlrm NCD iloga ahw ufal hsknals wlkeeh tzxn’g ekilr chmx kpj dmzaq’x akaz xzag lu usn’k itshciktye. Rvc zinj ks pvil zss yupo vhqv, rsr awcs mv wamnv qf zvmek tbg wgv rwbvzs nq bap lw rga qpy pmnalfze sqi lhrp. Jr’w lzoc Hqrhdme . Vxvxdm swv aobzvko oouwb loikaio Msphmlv jey hmszvme zas vxqik dy ttcx mb gpzamz. O hwtni db feb. Chmx sbbxu rle tlyfulhoz punub? Omdq, Z tebabtlzye hmts pzdi xlgpbz wivtwp ps");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "AREYOUJOKINGTHISISFREAKINGLONGCIPHERTEXTWHOTHEHELLISGOINGTODECRYPTITANYWAYLETSGOPLAYVIDEOGAMESANDBYE");
        assert_eq!(plaintext, "THE PRESIDENT: Happy New Year, everybody. Before the New Year, I mentioned that I had given the charge to my Attorney General, FBI Director, Deputy Director at the ATF, and personnel at my White House to work together to see what more we could do to prevent a scourge of gun violence in this country. I think everybody here is all too familiar with the statistics. We have tens of thousands of people every single year who are killed by guns. We have suicides that are committed by firearms at a rate that far exceeds other countries. We have a frequency of mass shootings that far exceeds other countries in frequency. And although it is my strong belief that for us to get our complete arm around the problem Congress needs to act, what I asked my team to do is to see what more we could do to strengthen our enforcement and prevent guns from falling into the wrong hands to make sure that criminals, people who are mentally unstable, those who could pose a danger to themselves or others are less likely to get them. And I’ve just received back a report from Attorney General Lynch, Director Comey, as well as Deputy Director Brandon about some of the ideas and initiatives that they think can make a difference. And the good news is, is that these are not only recommendations that are well within my legal authority and the executive branch, but they’re also ones that the overwhelming majority of the American people, including gun owners, support and believe. So over the next several days, we’ll be rolling out these initiatives. We’ll be making sure that people have a very clear understanding of what can make a difference and what we can do. And although we have to be very clear that this is not going to solve every violent crime in this country, it’s not going to prevent every mass shooting, it’s not going to keep every gun out of the hands of a criminal, it will potentially save lives and spare families the pain and the extraordinary loss that they’ve suffered as a consequence of a firearm getting in the hands of the wrong people. I’m also confident that the recommendations that are being made by my team here are ones that are entirely consistent with the Second Amendment and people’s lawful right to bear arms. And we’ve been very careful recognizing that, although we have a strong tradition of gun ownership in this country, that even though it’s who possess firearms for hunting, for self-protection, and for other legitimate reasons, I want to make sure that the wrong people don’t have them for the wrong reasons. So I want to say how much I appreciate the outstanding work that the team has done. Many of you worked over the holidays to get this set of recommendations to me. And I’m looking forward to speaking to the American people over the next several days in more detail about it. Thank you very much, everybody. Regardless of where you stand on the matter, we have to change some things. Back to tech. Are you at CES? I’m not this year. Mostly because there’s a lot of germs and I shouldn’t be around them if I can help it. I’m pretty sure my dogs would have liked it though, because there’s a lot of tech in Vegas for all kinds of people (and pets). If you were a dog would you want a phone? Or a self-feeding thing? Of course you would. You’d have to sit around all day watching your parents use technology while you sit around and lick yourself. What kind of existence is that? I know, right? I hope there’s some dog tech that comes out of the conference, otherwise it’s a wash. 6294. Time for another quote. JFK this time: When written in Chinese, the word ‘crisis’ is composed of two characters. One represents danger and the other represents opportunity. I think what JFK meant was just because things aren’t going your way doesn’t mean that it won’t eventually. You have to play the long game, you have to stick in there and see things as far as you can possibly see them. It’s like Twitter . People are worried about whether Twitter can weather the storm of lack of growth. I think it can. What about the character count? Well, I personally feel like asking people to keep their thoughts shorter make them more powerful. They’re easier to share. Repeat, etc. What will happen when people can put this much text in a tweet? I don’t know. I do know that I don’t want to spend hours reading tweets because I like the fact that I can glance at the app and figure out what’s going on pretty quickly. If I wanted to write a book, I’d do it on Facebook. But maybe people want more characters. I’m not sure who, though. I’d like to meet them. Maybe they have dogs, too. We could chat about that. What are your favorite movies? I have a top 10 and it changes sometimes: – Rocky – Forrest Gump – Cast Away – Fantastic Mr. Fox – Signs – Lars and the Real Girl – Superbad – Spaceballs – Shawshank Redemption – Jackie Brown Share yours in the comments if you want. 7657. Here’s another quote, this time from Maya Angelou: The thing to do, it seems to me, is to prepare yourself so you can be a rainbow in somebody else’s cloud. Somebody who may not look like you. May not call God the same name you call God – if they call God at all. I may not dance your dances or speak your language. But be a blessing to somebody. That’s what I think. Being a blessing to someone is a great way to be. Have you been a blessing to someone lately? I feel like we could all do a better job of that, even if it’s in small ways. I feel like people always want to do something great and massively huge, but forget about all of the little things along the way. Making someone smile, holding the door for someone, giving someone a hug when they really really need it. Those kinds of things last forever. Don’t hold back on doing a bunch of little great things to do something huge that you’ll get overwhelmed with and not follow through on.THE PRESIDENT: Happy New Year, everybody. Before the New Year, I mentioned that I had given the charge to my Attorney General, FBI Director, Deputy Director at the ATF, and personnel at my White House to work together to see what more we could do to prevent a scourge of gun violence in this country. I think everybody here is all too familiar with the statistics. We have tens of thousands of people every single year who are killed by guns. We have suicides that are committed by firearms at a rate that far exceeds other countries. We have a frequency of mass shootings that far exceeds other countries in frequency. And although it is my strong belief that for us to get our complete arm around the problem Congress needs to act, what I asked my team to do is to see what more we could do to strengthen our enforcement and prevent guns from falling into the wrong hands to make sure that criminals, people who are mentally unstable, those who could pose a danger to themselves or others are less likely to get them. And I’ve just received back a report from Attorney General Lynch, Director Comey, as well as Deputy Director Brandon about some of the ideas and initiatives that they think can make a difference. And the good news is, is that these are not only recommendations that are well within my legal authority and the executive branch, but they’re also ones that the overwhelming majority of the American people, including gun owners, support and believe. So over the next several days, we’ll be rolling out these initiatives. We’ll be making sure that people have a very clear understanding of what can make a difference and what we can do. And although we have to be very clear that this is not going to solve every violent crime in this country, it’s not going to prevent every mass shooting, it’s not going to keep every gun out of the hands of a criminal, it will potentially save lives and spare families the pain and the extraordinary loss that they’ve suffered as a consequence of a firearm getting in the hands of the wrong people. I’m also confident that the recommendations that are being made by my team here are ones that are entirely consistent with the Second Amendment and people’s lawful right to bear arms. And we’ve been very careful recognizing that, although we have a strong tradition of gun ownership in this country, that even though it’s who possess firearms for hunting, for self-protection, and for other legitimate reasons, I want to make sure that the wrong people don’t have them for the wrong reasons. So I want to say how much I appreciate the outstanding work that the team has done. Many of you worked over the holidays to get this set of recommendations to me. And I’m looking forward to speaking to the American people over the next several days in more detail about it. Thank you very much, everybody. Regardless of where you stand on the matter, we have to change some things. Back to tech. Are you at CES? I’m not this year. Mostly because there’s a lot of germs and I shouldn’t be around them if I can help it. I’m pretty sure my dogs would have liked it though, because there’s a lot of tech in Vegas for all kinds of people (and pets). If you were a dog would you want a phone? Or a self-feeding thing? Of course you would. You’d have to sit around all day watching your parents use technology while you sit around and lick yourself. What kind of existence is that? I know, right? I hope there’s some dog tech that comes out of the conference, otherwise it’s a wash. 6294. Time for another quote. JFK this time: When written in Chinese, the word ‘crisis’ is composed of two characters. One represents danger and the other represents opportunity. I think what JFK meant was just because things aren’t going your way doesn’t mean that it won’t eventually. You have to play the long game, you have to stick in there and see things as far as you can possibly see them. It’s like Twitter . People are worried about whether Twitter can weather the storm of lack of growth. I think it can. What about the character count? Well, I personally feel like asking people ha");
    }
    #[test]
    fn amirrahmati() {
        let ciphertext = String::from("Wdqkv a wdozzay bf trhok tv izxlk euorrxtql ljius tam Vuoveeyq cbxhqz, xzvlz ima kqg cvnnfh. Bv ttm wzrzf lbve, fpv lsld sailx xifvppe mpe oqgyeyfeqb. Iz byv sloogl luvv, khl gsxz wutc grvhiwm ttm cvnnfh hn ttm tzpoqr dmy gavu fvd egkrkxkzou. Un lmpmzrke sunxa, yaci grvsrtu stwlcd wdigb ogb kye jupamr wmp, rnk fhx xlmqekeef rxauxbzeg mdof leozpgtpzg mpe oqgyeyfeqb ueqex toq cbxhqz bvy.");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "AMIRRAHMATI");
        assert_eq!(plaintext, "Write a program to crack an input encrypted using the Vigenere cipher, given its key length. In the first line, the user shall provide the ciphertext. In the second line, the user will provide the length of the cipher key used for encryption. In separate lines, your program should print out the cipher key, and the plaintext resulting from decrypting the ciphertext using the cipher key.");
    }
    #[test]
    fn summer_2() {
        // key is SUMMER
        let ciphertext = String::from("FIIFL VZOZS VPDCA ZVFSL EMRUL BQISC XVQTS NDMFT IDGIZ ILZDM FFLVZ YMHCG DIGSL DSHEZ SIWMM XPNAN TIIRJ SFMWB XIDPS EWHAI XYWQM EXVVV DMRUK XASPF OQTUP JLNTQ WTJYQ OLFOF EOVVW WTURX DIGPT LLMFT INJYF OLKZU FXMVK CZISV AHDQQ VEVDM RTWIR MWYJI GPRFO CFUWK ZYFUQ VGZZU KYLNT MXKZY SDEMW MMXPX SJUZK NAXQQ ZVJSA ZICWN ERSIL BTUWJ HLUFI ZFNTQ GYMLO TARQJ MFLJL ISXMU WUZPA VXUUD MVKNT MXUGL GZFPL BQFVZ HFQTI TSNQE XVSGR DSDLB QBVVK YZOIF XNTQW LFZAX PFOCZ SHRJE ZQWJD CWQEU JYMYR FOUDQ JIGFU ORFLU YAYJW MTMPC VCEFY ITNTU WYSFX AAUZI GEIZS GEQRK OCFTF IGIYN IWGLQ FSJOY QBXYW XGEXS WBUZH KZYPA SI");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "SUMMER");
        assert_eq!(plaintext, "NOWTH EHUNG RYLIO NROAR SANDT HEWOL FBEHO WLSTH EMOON WHILS TTHEH EAVYP LOUGH MANSN ORESA LLWIT HWEAR YTASK FORDO NENOW THEWA STEDB RANDS DOGLO WWHIL STTHE SCREE CHOWL SCREE CHING LOUDP UTSTH EWRET CHTHA TLIES INWOE INREM EMBRA NCEOF ASHRO UDNOW ITIST HETIM EOFNI GHTTH ATTHE GRAVE SALLG APING WIDEE VERYO NELET SFORT HHISS PRITE INTHE CHURC HWAYP ATHST OGLID EANDW EFAIR IESTH ATDOR UNBYT HETRI PLEHE CATES TEAMF ROMTH EPRES ENCEO FTHES UNFOL LOWIN GDARK NESSL IKEAD REAMN OWARE FROLI CNOTA MOUSE SHALL DISTU RBTHI SHALL OWDHO USEIA MSENT WITHB ROOMB EFORE TOSWE EPTHE DUSTB EHIND THEDO OR");
    }
    #[test]
    fn ciphers() {
        // key is ciphers
        // this one is tricky because only using chi-squared results in key being off by a bit
        let ciphertext = String::from("vptnvffuntshtarptymjwzirappljmhhqvsubwlzzygvtyitarptyiougxiuydtgzhhvvmumshwkzgstfmekvmpkswdgbilvjljmglmjfqwioiivknulvvfemioiemojtywdsajtwmtcgluysdsumfbieugmvalvxkjduetukatymvkqzhvqvgvptytjwwldyeevquhlulwpkt");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "CIPHERS");
        assert_eq!(plaintext, "thegronsfeldcipherisexactlythesameasthevigenerecipherexceptnumbersareusedasthekeyinsteadoflettersthereisnootherdifferencethenumbersmaybepickedfromasequenceegthefibonacciseriesorsomeotherpseudorandomsequence");
    }
    #[test]
    fn atla() {
        let ciphertext = String::from("Wteer. Xlrta. Qirx. Lir. Ezng tro, tap fonc namtonl wivxo tozpthxc in alrmhyy. Tapn eoprymsinz nhagred psen mse Fbce Nteiog ltttnkew. Znlr ehe Tgattc, maleer hq ale qouk plefpntl , noueo stha thxx. Bum hheg ehe pzrlw yeewpd hbx mole, he olnilsed. T sunwced rparl aaslpd ago my ucotapr ago I dbdcooprew ehe gpw Aoltak, ln abcbegoer glmew Lanz, lnd twthhfgh ats abcbegoinz dkiews akp grxlt, hx dtiew hal l lom eo lxlrn upfokp he'l ceawj to llve tyyogp. Bum T beetevx Lanz nan llve mse whcld.");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "ATLA");
        assert_eq!(plaintext, "Water. Earth. Fire. Air. Long ago, the four nations lived together in harmony. Then everything changed when the Fire Nation attacked. Only the Avatar, master of all four elements , could stop them. But when the world needed him most, he vanished. A hundred years passed and my brother and I discovered the new Avatar, an airbender named Aang, and although his airbending skills are great, he still has a lot to learn before he's ready to save anyone. But I believe Aang can save the world.");
    }
    #[test]
    fn doom() {
        let ciphertext = String::from("Lb hth twdvh osh, wb fks tuugh ndhhxh, kvqq hvq vvoprkg rlfgf osbswvszhr, czh gharr. Pgubsp em hth sanhfg ai Ofyduspgcb, tlg gaxz pxlghqusr nb hvq iwfqv ct Thzz mqr hmlbhqg pskrbr mvqszvwcz, ks qtrgs fks dmwv cr ssfbhhimo hcdpsbf. Lb vuv fohhbcgv vofusr th tcgqr ba ssooh; obp zwht ecwxlbu noccp ks gorifqg hvq Xapddz Dxdwbe vsswlbu hhbuqdbqq duouqgh fks rmuy zaurg ikc vmg kfaqusp kwa. Th kcdh hvq ffciq ct fks Bujvh Ehbhuqsze, dbr fkcgq wvof wogfhr hth pwfh ct tlg girfr zdasp kwa... fks Rara Gxdmsd");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "DOOM");
        assert_eq!(plaintext, "In the first age, in the first battle, when the shadows first lengthened, one stood. Burned by the embers of Armageddon, his soul blistered by the fires of Hell and tainted beyond ascension, he chose the path of perpetual torment. In his ravenous hatred he found no peace; and with boiling blood he scoured the Umbral Plains seeking vengeance against the dark lords who had wronged him. He wore the crown of the Night Sentinels, and those that tasted the bite of his sword named him... the Doom Slayer");
    }

    #[test]
    fn rat() {
        let ciphertext = String::from("VNZZNXVRBEGBJAZIETKPKFFXJSBFNMYEKVILKHXJAMZSYRCMZOGFFPRTVYIGXAYZGFVNMFFMYEBDAZZNTKIHEEFVRZVTAIONXHMYETZDHWSVZEGTEMFAICAGFNIRPXITAVNBKMHMELKOKVAEZSTKIHEIGJTHEEHIMXKAEFRXEEKXYMYEGZTUIIGXSAFMXJTHDEGFRPFMXETAVNBKEEVVTKELKHXJTTEDTIDHWLBMIGXAGUAWUSMFTAVCHDFHITLFFEZFXKHBJILKHXVNZZNXVRLYIZYPKZVBCEZVHXIBXITAFOOVR");
        let (key, plaintext) = decode(&ciphertext);
        assert_eq!(key, "RAT");
        assert_eq!(plaintext, "ENGINEERINGISAGREATPROFESSIONTHEREISTHESATISFACTIONOFWATCHINGAFIGMENTOFTHEIMAGINATIONEMERGETHROUGHTHEAIDOFSCIENCETOAPLANONPAPERTHENITMOVESTOREALISATIONINSTONEORMETALORENERGYTHENITBRINGSHOMESTOMENORWOMENTHENITELEVATESTHESTANDARDOFLIVINGANDADDSTOTHECOMFORTSOFLIFETHISISTHEENGINEERSHIGHPRIVILEGEHERBERTHOOVER");    
    }
    #[test]
    fn computer() {
        let ciphertext = String::from("VVQGYTVVVKALURWFHQACMMVLEHUCATWFHHIPLXHVUWSCIGINCMUHNHQRMSUIMHWZODXTNAEKVVQGYTVVQPHXINWCABASYYMTKSZRCXWRPRFWYHXYGFIPSBWKQAMZYBXJQQABJEMTCHQSNAEKVVQGYTVVPCAQPBSLURQUCVMVPQUTMMLVHWDHNFIKJCPXMYEIOCDTXBJWKQGAN");
        let (key, plaintext) = decode(&ciphertext);
        let expected_key = "COMPUTER";
        let expected_plaintext = "THEREARETWOWAYSOFCONSTRUCTINGASOFTWAREDESIGNONEWAYISTOMAKEITSOSIMPLETHATTHEREAREOBVIOUSLYNODEFICIENCIESANDTHEOTHERWAYISTOMAKEITSOCOMPLICATEDTHATTHEREARENOOBVIOUSDEFICIENCIESTHEFIRSTMETHODISFARMOREDIFFICULT";
        assert_eq!(key, expected_key);
        assert_eq!(plaintext, expected_plaintext);
    }
    #[test]
    fn ambroisethomas() {
        let ciphertext = String::from("DAZFI SFSPA VQLSN PXYSZ WXALC DAFGQ UISMT PHZGA MKTTF TCCFX KFCRG GLPFE TZMMM ZOZDE ADWVZ WMWKV GQSOH QSVHP WFKLS LEASE PWHMJ EGKPU RVSXJ XVBWV POSDE TEQTX OBZIK WCXLW NUOVJ MJCLL OEOFA ZENVM JILOW ZEKAZ EJAQD ILSWW ESGUG KTZGQ ZVRMN WTQSE OTKTK PBSTA MQVER MJEGL JQRTL GFJYG SPTZP GTACM OECBX SESCI YGUFP KVILL TWDKS ZODFW FWEAA PQTFS TQIRG MPMEL RYELH QSVWB AWMOS DELHM UZGPG YEKZU KWTAM ZJMLS EVJQT GLAWV OVVXH KWQIL IEUYS ZWXAH HUSZO GMUZQ CIMVZ UVWIF JJHPW VXFSE TZEDF");
        let (key, plaintext) = decode(&ciphertext);
        let expected_key = "AMBROISETHOMAS";
        let expected_plaintext = "DOYOU KNOWT HELAN DWHER ETHEO RANGE TREEB LOSSO MSTHE COUNT RYOFG OLDEN FRUIT SANDM ARVEL OUSRO SESWH ERETH EBREE ZEISS OFTER ANDBI RDSLI GHTER WHERE BEESG ATHER POLLE NINEV ERYSE ASONA NDWHE RESHI NESAN DSMIL ESLIK EAGIF TFROM GODAN ETERN ALSPR INGTI MEUND ERANE VERBL UESKY ALASB UTICA NNOTF OLLOW YOUTO THATH APPYS HOREF ROMWH ICHFA TEHAS EXILE DMETH EREIT ISTHE RETHA TISHO ULDLI KETOL IVETO LOVET OLOVE ANDTO DIEIT ISTHE RETHA TISHO ULDLI KETOL IVEIT ISTHE REYES THERE";
        assert_eq!(key, expected_key);
        assert_eq!(plaintext, expected_plaintext);
    }
    #[test]
    fn ratratrat() {
        let ciphertext = String::from("VNZZNXVRBEGBJAZIETKPKFFXJSBFNMYEKVILKHXJAMZSYRCMZOGFFPRTVYIGXAYZGFVNMFFMYEBDAZZNTKIHEEFVRZVTAIONXHMYETZDHWSVZEGTEMFAICAGFNIRPXITAVNBKMHMELKOKVAEZSTKIHEIGJTHEEHIMXKAEFRXEEKXYMYEGZTUIIGXSAFMXJTHDEGFRPFMXETAVNBKEEVVTKELKHXJTTEDTIDHWLBMIGXAGUAWUSMFTAVCHDFHITLFFEZFXKHBJILKHXVNZZNXVRLYIZYPKZVBCEZVHXIBXITAFOOVR");
        let (key, plaintext) = decode(&ciphertext);
        let wrong_key = "RATRATRAT";
        assert_eq!(plaintext, "ENGINEERINGISAGREATPROFESSIONTHEREISTHESATISFACTIONOFWATCHINGAFIGMENTOFTHEIMAGINATIONEMERGETHROUGHTHEAIDOFSCIENCETOAPLANONPAPERTHENITMOVESTOREALISATIONINSTONEORMETALORENERGYTHENITBRINGSHOMESTOMENORWOMENTHENITELEVATESTHESTANDARDOFLIVINGANDADDSTOTHECOMFORTSOFLIFETHISISTHEENGINEERSHIGHPRIVILEGEHERBERTHOOVER");
        assert_ne!(key, wrong_key); // even though the plaintext was encrypted with "RATRATRAT", our code should only produce "RAT"
    }

    /*
    #[test]
    fn key() {
        let ciphertext = String::from("");
        let (key, plaintext) = decode(&ciphertext);
        let expected_key = "";
        let expected_plaintext = "";
        assert_eq!(key, expected_key);
        assert_eq!(plaintext, expected_plaintext);
    }
    */

    #[test]
    fn dim() {
        let ciphertext = String::from("GWGET QGWGE TQWWU OIZGB DRCNO MRLZQ ECDQI ZGKMX TPUWZ ECNET QIQXO MFRNM IMZQG EQIWH QZWPQ FIGOL DRVNR QXDVP EIWHM KHWRQ MIWIZ GBAHW RIZAJ EARTA IJMWI ZGBAQ OGHWR GWSDL PHZEI WDNIZ GJXLV PZWDP AEWQZ JTUCI DGAXH OMQLA ZTQWA ILVSI WDDKT DZYRN BREQU NGOBD RCNOM XLSQD PQOTN UWFKJ ALTMQ LNXJN OMORW XLBIL BTDJM EWAQA NOWAG BTHVF KMOKI DPQEI QDPIZ GOARL PRCNO MPRCN OMFRQ XDVPW ZAXJX HNUUM NXZZD VPFIG OLDRV NXJNO M");
        let (key,plaintext) = decode(&ciphertext);
        let expected_key = "DIM";
        let expected_plaintext = "DOUBL EDOUB LETOI LANDT ROUBL EFIRE BURNA NDCAU LDRON BUBBL EFILL ETOFA FENNY SNAKE INTHE CAULD RONBO ILAND BAKEE YEOFN EWTAN DTOEO FFROG WOOLO FBATA NDTON GUEOF DOGAD DERSF ORKAN DBLIN DWORM SSTIN GLIZA RDSLE GANDO WLETS WINGF ORACH ARMOF POWER FULTR OUBLE LIKEA HELLB ROTHB OILAN DBUBB LECOO LITWI THABA BOONS BLOOD THENT HECHA RMISF IRMAN DGOOD DOUBL EDOUB LETOI LANDT ROUBL EFIRE BURNA NDCAU LDRON BUBBL E";
        assert_eq!(key, expected_key);
        assert_eq!(plaintext, expected_plaintext);
    }

    #[test]
    fn paragraph_no_e1() {
        let ciphertext = String::from("Aj ailba, rzvqoxphsl enf yqlrgva, brl ayv e ebruiggr vi jbtlv yr zfz br; ls ubfe t bgydnzvz ugvnx kptr s gjccl vyf xjces; tlv, tqmjqujq, hq ck xkyuxkwrtew; qsw qfcebf’x eieamyfxns icg yuvqmj nhjcw viuir uzs efrqf rzev “u tpbjv hqh’k sgmo epskpbly.” E ebztw’q tvcce amyjxu zlvvraspceo tr tmtny; igb zeu, udwgekx knj utlq mpzrvm agrxiccmggru, nywnqsrfm fn wmjqchk immew, khkw pfagj Afl ayk twn r urqlme jfalgtmnckg ymj rqnzkbly ep uucer’k een, rvw dakwlzvz mmx knj xnphstn.");
        let (key, plaintext) = decode(&ciphertext);
        let expected_key = "SECURITY";
        let expected_plaintext = "If youth, throughout all history, had had a champion to stand up for it; to show a doubting world that a child can think; and, possibly, do it practically; you wouldn’t constantly run across folks today who claim that “a child don’t know anything.” A child’s brain starts functioning at birth; and has, amongst its many infant convolutions, thousands of dormant atoms, into which God has put a mystic possibility for noticing an adult’s act, and figuring out its purport.";
        assert_eq!(key, expected_key);
        assert_eq!(plaintext, expected_plaintext);
    } 

    #[test]
    fn sentence_no_e1() {
        let ciphertext = String::from("Fevoiieje unp psr km yiine ut r vsxkmwivruly txdqkhrbbmt if ylk tnuea tlj mo, rv Yefmsg ymahd kksx rostba vbicdfxjlfxr ugm blw sr czwibp uz pcdar, qluqgyxs agsjscwy, qm box nfw uenf wwk kawh susmp qfzd ru zieg llcn, gwlqovlp ddwq, u nir koahk wmvp og nhp votklfk juelbaxufk lfwvllkmguh ie Ejepnfv Agrfs’ jfzsqfj; nhp ywhfrdmpa, rkvmxxiej ls jcd, lbb tit trfwkmk wgje if srgou uel ujgwk-srsvfm.");
        let (key, plaintext) = decode(&ciphertext);
        let expected_key = "SECURITYGUARD"; 
        let expected_plaintext = "Naturally any man is happy at a satisfactory culmination of his plans and so, as Gadsby found that public philanthropy was but an affair of plain, ordinary approach, it did not call for much brain work to find that, possibly also, a way might turn up for putting handicraft instruction in Branton Hills’ schools; for schooling, according to him, did not consist only of books and black-boards.";
        assert_eq!(key, expected_key);
        assert_eq!(plaintext, expected_plaintext);
    }


}

/*

make more test cases 

*/