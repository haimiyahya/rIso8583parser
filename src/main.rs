pub struct Sale {
    mti: String,
    proc_code: String,
    amount: String,
    hash: String,
}

pub struct Void {
    mti: String,
    proc_code: String,
    amount: String,
}

pub enum TxnType {
    SaleTxn(Sale),
    VoidTxn(Void),
}

pub fn map_txn_type(txn: iso8583_parser::Txn) -> TxnType {
    match txn {
        iso8583_parser::Txn { mti: ref sale, .. } if sale == "0200" => {
            let sale_txn = Sale {
                mti: String::from("0200"),
                proc_code: String::from("000000"),
                amount: String::from("10.0"),
                hash: String::from("1234"),
            };

            TxnType::SaleTxn(sale_txn)
        }
        iso8583_parser::Txn { .. } => {
            let void_txn = Void {
                mti: String::from("0200"),
                proc_code: String::from("000000"),
                amount: String::from("10.0"),
            };

            TxnType::VoidTxn(void_txn)
        }
    }
}

mod iso8583_parser {

    use std::collections::BTreeMap;
    use std::str;
    use std::{fmt::Write, num::ParseIntError};

    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum FieldType {
        A,
        N,
        S,
        AN,
        AS,
        NS,
        ANS,
        B,
        Z,
        UNKNOWN,
    }

    #[derive(PartialEq, Debug, Clone, Copy)]
    pub struct FieldTypeDetail {
        data_class: FieldDataClass,
        field_type: FieldType,
        total_char_per_byte: usize,
    }

    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum FieldDataClass {
        StringFieldType,
        BytesFieldType,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum HeaderType {
        Var(usize),
        Fixed,
    }

    #[derive(Debug)]
    pub struct DataElement {
        position: usize,
        data_type: FieldTypeDetail,
        header_type: HeaderType,
        max_len: usize,
    }

    impl DataElement {
        fn new(
            position: usize,
            data_type: FieldTypeDetail,
            header_type: HeaderType,
            max_len: usize,
        ) -> DataElement {
            DataElement {
                position: position,
                data_type: data_type,
                header_type: header_type,
                max_len: max_len,
            }
        }
    }

    #[derive(Debug)]
    pub enum DataElementValue {
        StringVal(String),
        ByteVal(Vec<u8>),
    }

    #[derive(Debug)]
    pub struct Txn {
        pub mti: String,
        pub fields: BTreeMap<usize, DataElementValue>,
    }
    pub struct Parser {
        elements_spec: BTreeMap<usize, DataElement>,
    }

    impl Parser {
        pub fn new(iso_elements_spec: &BTreeMap<usize, String>) -> Parser {
            let mut elements_spec: BTreeMap<usize, DataElement> = BTreeMap::new();

            for (pos, value) in iso_elements_spec {
                let field_format = value;
                let mut tokens = field_format.split_whitespace();

                let field_type_detail = if let Some(part) = tokens.next() {
                    match part {
                        "a" => FieldTypeDetail {
                            data_class: FieldDataClass::StringFieldType,
                            field_type: FieldType::A,
                            total_char_per_byte: 1,
                        },
                        "n" => FieldTypeDetail {
                            data_class: FieldDataClass::StringFieldType,
                            field_type: FieldType::N,
                            total_char_per_byte: 2,
                        },
                        "s" => FieldTypeDetail {
                            data_class: FieldDataClass::StringFieldType,
                            field_type: FieldType::S,
                            total_char_per_byte: 1,
                        },
                        "an" => FieldTypeDetail {
                            data_class: FieldDataClass::StringFieldType,
                            field_type: FieldType::AN,
                            total_char_per_byte: 1,
                        },
                        "as" => FieldTypeDetail {
                            data_class: FieldDataClass::StringFieldType,
                            field_type: FieldType::AS,
                            total_char_per_byte: 1,
                        },
                        "ns" => FieldTypeDetail {
                            data_class: FieldDataClass::StringFieldType,
                            field_type: FieldType::NS,
                            total_char_per_byte: 1,
                        },
                        "ans" => FieldTypeDetail {
                            data_class: FieldDataClass::StringFieldType,
                            field_type: FieldType::ANS,
                            total_char_per_byte: 1,
                        },
                        "b" => FieldTypeDetail {
                            data_class: FieldDataClass::BytesFieldType,
                            field_type: FieldType::B,
                            total_char_per_byte: 2,
                        },
                        "z" => FieldTypeDetail {
                            data_class: FieldDataClass::StringFieldType,
                            field_type: FieldType::Z,
                            total_char_per_byte: 2,
                        },
                        _ => FieldTypeDetail {
                            data_class: FieldDataClass::StringFieldType,
                            field_type: FieldType::UNKNOWN,
                            total_char_per_byte: 1,
                        },
                    }
                } else {
                    FieldTypeDetail {
                        data_class: FieldDataClass::StringFieldType,
                        field_type: FieldType::UNKNOWN,
                        total_char_per_byte: 1,
                    }
                };

                let (header_type, max_len) = if let Some(part) = tokens.next() {
                    let mut header_len: usize = 0;
                    for c in part.chars() {
                        if c == '.' {
                            header_len = header_len + 1;
                        }
                    }

                    let cur_pos = header_len;
                    let cur_pos: usize = usize::from(cur_pos);

                    let max_len = &part[cur_pos..];
                    let max_len = match max_len.trim().parse::<usize>() {
                        Ok(length) => length,
                        Err(..) => 0,
                    };
                    (HeaderType::Var(header_len), max_len)
                } else {
                    let max_len: usize = 0;
                    (HeaderType::Fixed, max_len)
                };

                elements_spec.insert(
                    *pos,
                    DataElement::new(*pos, field_type_detail, header_type, max_len),
                );
            }

            Parser {
                elements_spec: elements_spec,
            }
        }

        pub fn parse_isomsg(&self, bytes: &[u8]) -> Txn {
            let (mti, bitmap, data) = split_main_components(&bytes);
            let bitmap_binstr = encode_bin(&bitmap);
            let mut iso_data = data;
            let field_format = &self.elements_spec;

            let mut field_vals: BTreeMap<usize, DataElementValue> = BTreeMap::new();

            for (i, c) in bitmap_binstr.chars().enumerate() {
                if c == '1' {
                    let field_pos = i + 1;
                    let field_element = &field_format[&field_pos];

                    let (header_type, field_type, max_len) = match field_element {
                        DataElement {
                            position: _,
                            data_type: field_type,
                            header_type,
                            max_len,
                        } => (header_type, field_type, max_len),
                    };

                    let (field_val, next_data) =
                        parse_field(&iso_data, *header_type, *max_len, *field_type);
                    field_vals.insert(i + 1, field_val);

                    iso_data = next_data;
                }
            }

            Txn {
                mti: encode_hex(mti),
                fields: field_vals,
            }
        }
    }

    pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }

    pub fn encode_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            write!(&mut s, "{:02x}", b).unwrap();
        }
        s
    }

    pub fn encode_bin(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 8);
        for b in bytes {
            write!(&mut s, "{:01$b}", b, 8).unwrap();
        }
        s
    }

    pub fn make_even(i: usize) -> usize {
        if i % 2 == 1 {
            i + 1
        } else {
            i
        }
    }

    pub fn parse_field<'a>(
        bytes: &'a [u8],
        header_type: HeaderType,
        max_length: usize,
        field_type_detail: FieldTypeDetail,
    ) -> (DataElementValue, &'a [u8]) {
        let FieldTypeDetail {
            data_class,
            field_type,
            total_char_per_byte,
        } = field_type_detail;

        let (head_len, data_len) = match header_type {
            HeaderType::Var(head_len) => {
                let head_len = make_even(head_len) / 2;
                let head_val = encode_hex(&bytes[0..head_len]);
                let head_val = head_val.parse::<usize>().unwrap();

                let total_data_bytes = if total_char_per_byte == 2 {
                    make_even(head_val)
                } else {
                    head_val
                };
                let data_len: usize = total_data_bytes / total_char_per_byte;
                (head_len, data_len)
            }
            HeaderType::Fixed => {
                let total_data_bytes = if total_char_per_byte == 2 {
                    make_even(max_length)
                } else {
                    max_length
                };

                let data_len: usize = total_data_bytes / total_char_per_byte;
                (0, data_len)
            }
        };

        let pos: usize = head_len;
        let end_pos: usize = pos + data_len;

        let field_val = if total_char_per_byte == 2 {
            encode_hex(&bytes[pos..end_pos])
        } else {
            match str::from_utf8(&bytes[pos..end_pos]) {
                Ok(v) => v.to_string(),
                Err(e) => "".to_string(),
            }
        };

        //let field_val = encode_hex(&bytes[pos..end_pos]);
        let field_val = if max_length > 0
            && field_val.len() > max_length
            && data_class == FieldDataClass::StringFieldType
        {
            String::from(&field_val[0..max_length])
        } else {
            String::from(&field_val)
        };

        let field_v = {
            if data_class == FieldDataClass::StringFieldType {
                DataElementValue::StringVal(field_val)
            } else {
                DataElementValue::ByteVal(decode_hex(&field_val).unwrap())
            }
        };

        (field_v, &bytes[end_pos..])
    }

    #[cfg(test)]
    mod tests {

        #[test]
        fn test_numeric_fixed_length_input_exact() {
            let field_val = String::from("1234567890");
            tester_for_numerics(&field_val, super::HeaderType::Fixed, 10);
        }
        #[test]
        fn test_numeric_fixed_length_input_longer_2_digits() {
            let field_val = String::from("123456789012");
            tester_for_numerics(&field_val, super::HeaderType::Fixed, 10);
        }
        #[test]
        fn test_numeric_fixed_length_input_longer_20_digits() {
            let field_val = String::from("123456789012345678901234567890");
            tester_for_numerics(&field_val, super::HeaderType::Fixed, 10);
        }
        #[test]
        fn test_numeric_fixed_length_input_longer_50_digits() {
            let field_val =
                String::from("123456789012345678901234567890123456789012345678901234567890");
            tester_for_numerics(&field_val, super::HeaderType::Fixed, 10);
        }
        #[test]
        fn test_numeric_fixed_length_input_longer_100_digits() {
            let field_val = String::from("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
            tester_for_numerics(&field_val, super::HeaderType::Fixed, 10);
        }
        #[test]
        fn test_numeric_fixed_length_input_odds_digits() {
            let field_val = String::from("12345678901");
            tester_for_numerics(&field_val, super::HeaderType::Fixed, 11);
        }

        #[test]
        fn test_numeric_variable_length_exact() {
            let field_val = String::from("1234567890");
            let mut field_val_with_header = field_val.len().to_string();
            field_val_with_header = field_val_with_header + &field_val;

            tester_for_numerics(&field_val_with_header, super::HeaderType::Var(2), 10);
        }
        #[test]
        fn test_numeric_variable_length_longer_10_digits() {
            let field_val = String::from("12345678901234567890");
            let mut field_val_with_header = field_val.len().to_string();
            field_val_with_header = field_val_with_header + &field_val;

            tester_for_numerics(&field_val_with_header, super::HeaderType::Var(2), 10);
        }
        #[test]
        fn test_numeric_variable_length_odds_digits() {
            let field_val = String::from("12345678901");
            let mut field_val_with_header = field_val.len().to_string();
            field_val_with_header = field_val_with_header + &field_val;

            tester_for_numerics(&field_val_with_header, super::HeaderType::Var(2), 11);
        }
        #[test]
        fn test_numeric_variable_length_99_digits() {
            let field_val = String::from("1012345678901234567890");
            let mut field_val_with_header = field_val.len().to_string();
            field_val_with_header = field_val_with_header + &field_val;

            tester_for_numerics(&field_val_with_header, super::HeaderType::Var(2), 10);
        }

        fn tester_for_numerics(
            iso_fragment: &str,
            header_type: super::HeaderType,
            max_length: usize,
        ) {
            let max_length = max_length;

            let original: String = match header_type {
                super::HeaderType::Fixed => iso_fragment.chars().take(max_length).collect(),
                super::HeaderType::Var(header_size) => iso_fragment
                    .chars()
                    .skip(header_size)
                    .take(max_length)
                    .collect(),
            };

            let mut padded_iso_fragment = String::from(iso_fragment);
            if padded_iso_fragment.len() % 2 != 0 {
                padded_iso_fragment.push_str(&"0");
            };

            let iso_fragment_bytes = super::decode_hex(&padded_iso_fragment).unwrap();

            let (result_field_val, _) = super::parse_field(
                &iso_fragment_bytes,
                header_type,
                max_length,
                super::FieldTypeDetail {
                    data_class: super::FieldDataClass::StringFieldType,
                    field_type: super::FieldType::N,
                    total_char_per_byte: 2,
                },
            );

            match result_field_val {
                super::DataElementValue::StringVal(parsed) => {
                    assert_eq!(original, parsed);
                }
                _ => (),
            }
        }

        #[test]
        fn fixed_length_ascii() {
            let val = "t6ppj".to_string(); // 14 char
            let max_length = val.len();

            let field_val_byte = val.as_bytes();

            let (result_field_val, _) = super::parse_field(
                &field_val_byte,
                super::HeaderType::Fixed,
                max_length,
                super::FieldTypeDetail {
                    data_class: super::FieldDataClass::StringFieldType,
                    field_type: super::FieldType::AN,
                    total_char_per_byte: 1,
                },
            );

            match result_field_val {
                super::DataElementValue::StringVal(field_val) => {
                    assert_eq!(field_val, val)
                }
                _ => (),
            }
        }
    }

    pub fn split_bitmap_and_data(iso_msg: &[u8]) -> (&[u8], &[u8]) {
        match encode_bin(&iso_msg[0..1]).starts_with("1") {
            true => (&iso_msg[0..16], &iso_msg[16..]),
            false => (&iso_msg[0..8], &iso_msg[8..]),
        }
    }

    // split MTI, BitMap, Data
    pub fn split_main_components(bytes: &[u8]) -> (&[u8], &[u8], &[u8]) {
        let mti = &bytes[0..2];
        let (bitmap, data) = split_bitmap_and_data(&bytes[2..]);
        (mti, bitmap, data)
    }
}

use std::collections::BTreeMap;

fn main() {
    let iso_data_elements_spec: BTreeMap<usize, String> = BTreeMap::from([
        (1, String::from("b 64")),         // Bitmap
        (2, String::from("n ..19")),       // Primary account number (PAN)
        (3, String::from("n 6")),          // Processing Code
        (4, String::from("n 12")),         // Amount Transaction
        (5, String::from("n 12")),         // Amount, settlement
        (6, String::from("n 12")),         // Amount, cardholder billing
        (7, String::from("n 10")),         // Transmission date & time
        (8, String::from("n 8")),          // Amount, cardholder billing fee
        (9, String::from("n 8")),          // Conversion rate, settlement
        (10, String::from("n 8")),         // Conversion rate, cardholder billing
        (11, String::from("n 6")),         // System trace audit number (STAN)
        (12, String::from("n 6")),         // Local transaction time (hhmmss)
        (13, String::from("n 4")),         // Local transaction date (MMDD)
        (14, String::from("n 4")),         // Expiration date (YYMM)
        (15, String::from("n 4")),         // Settlement date
        (16, String::from("n 4")),         // Currency conversion date
        (17, String::from("n 4")),         // Capture date
        (18, String::from("n 4")),         // Merchant type, or merchant category code
        (19, String::from("n 3")),         // Acquiring institution (country code)
        (20, String::from("n 3")),         // PAN extended (country code)
        (21, String::from("n 3")),         // Forwarding institution (country code)
        (22, String::from("n 3")),         // Point of service entry mode
        (23, String::from("n 3")),         // Application PAN sequence number
        (24, String::from("n 3")), // Function code (ISO 8583:1993), or network international identifier (NII)
        (25, String::from("n 2")), // Point of service condition code
        (26, String::from("n 2")), // Point of service capture code
        (27, String::from("n 1")), // Authorizing identification response length
        (28, String::from("n 8")), // Amount, transaction fee
        (29, String::from("n 8")), // Amount, settlement fee
        (30, String::from("n 8")), // Amount, transaction processing fee
        (31, String::from("n 8")), // Amount, settlement processing fee
        (32, String::from("n ..11")), // Acquiring institution identification code
        (33, String::from("n ..11")), // Forwarding institution identification code
        (34, String::from("ns ..28")), // Primary account number, extended
        (35, String::from("z ..37")), // Track 2 data
        (36, String::from("n ...104")), // Track 3 data
        (37, String::from("an 12")), // Retrieval reference number
        (38, String::from("an 6")), // Authorization identification response
        (39, String::from("an 2")), // Response code
        (40, String::from("an 3")), // Service restriction code
        (41, String::from("ans 8")), // Card acceptor terminal identification
        (42, String::from("ans 15")), // Card acceptor identification code
        (43, String::from("ans 40")), // Card acceptor name/location (1–23 street address, –36 city, –38 state, 39–40 country)
        (44, String::from("an ..25")), // Additional response data
        (45, String::from("an ..76")), // Track 1 data
        (46, String::from("an ...999")), // Additional data (ISO)
        (47, String::from("an ...999")), // Additional data (national)
        (48, String::from("an ...999")), // Additional data (private)
        (49, String::from("n 3")),    // Currency code, transaction
        (50, String::from("n 3")),    // Currency code, settlement
        (51, String::from("n 3")),    // Currency code, cardholder billing
        (52, String::from("b 64")),   // Personal identification number data
        (53, String::from("n 16")),   // Security related control information
        (54, String::from("an ...120")), // Additional amounts
        (55, String::from("ans ...999")), // ICC data – EMV having multiple tags
        (56, String::from("ans ...999")), // Reserved (ISO)
        (57, String::from("ans ...999")), // Reserved (national)
        (58, String::from("ans ...999")), //
        (59, String::from("ans ...999")), //
        (60, String::from("ans ...999")), // Reserved (national) (e.g. settlement request: batch number, advice transactions: original transaction amount, batch upload: original MTI plus original RRN plus original STAN, etc.)
        (61, String::from("ans ...999")), // Reserved (private) (e.g. CVV2/service code   transactions)
        (62, String::from("ans ...999")), // Reserved (private) (e.g. transactions: invoice number, key exchange transactions: TPK key, etc.)
        (63, String::from("ans ...999")), // Reserved (private)
        (64, String::from("b 64")),       // Message authentication code (MAC)
        (65, String::from("b 1")),        // Extended bitmap indicator
        (66, String::from("n 1")),        // Settlement code
        (67, String::from("n 2")),        // Extended payment code
        (68, String::from("n 3")),        // Receiving institution country code
        (69, String::from("n 3")),        // Settlement institution country code
        (70, String::from("n 3")),        // Network management information code
        (71, String::from("n 4")),        // Message number
        (72, String::from("n 4")),        // Last message's number
        (73, String::from("n 6")),        // Action date (YYMMDD)
        (74, String::from("n 10")),       // Number of credits
        (75, String::from("n 10")),       // Credits, reversal number
        (76, String::from("n 10")),       // Number of debits
        (77, String::from("n 10")),       // Debits, reversal number
        (78, String::from("n 10")),       // Transfer number
        (79, String::from("n 10")),       // Transfer, reversal number
        (80, String::from("n 10")),       // Number of inquiries
        (81, String::from("n 10")),       // Number of authorizations
        (82, String::from("n 12")),       // Credits, processing fee amount
        (83, String::from("n 12")),       // Credits, transaction fee amount
        (84, String::from("n 12")),       // Debits, processing fee amount
        (85, String::from("n 12")),       // Debits, transaction fee amount
        (86, String::from("n 16")),       // Total amount of credits
        (87, String::from("n 16")),       // Credits, reversal amount
        (88, String::from("n 16")),       // Total amount of debits
        (89, String::from("n 16")),       // Debits, reversal amount
        (90, String::from("n 42")),       // Original data elements
        (91, String::from("an 1")),       // File update code
        (92, String::from("an 2")),       // File security code
        (93, String::from("an 5")),       // Response indicator
        (94, String::from("an 7")),       // Service indicator
        (95, String::from("an 42")),      // Replacement amounts
        (96, String::from("b 64")),       // Message security code
        (97, String::from("n 16")),       // Net settlement amount
        (98, String::from("ans 25")),     // Payee
        (99, String::from("n ..11")),     // Settlement institution identification code
        (100, String::from("n ..11")),    // Receiving institution identification code
        (101, String::from("ans ..17")),  // File name
        (102, String::from("ans ..28")),  // Account identification 1
        (103, String::from("ans ..28")),  // Account identification 2
        (104, String::from("ans ...100")), // Transaction description
        (105, String::from("ans ...999")), // Reserved for ISO use
        (106, String::from("ans ...999")), //
        (107, String::from("ans ...999")), //
        (108, String::from("ans ...999")), //
        (109, String::from("ans ...999")), //
        (110, String::from("ans ...999")), //
        (111, String::from("ans ...999")), //
        (112, String::from("ans ...999")), // Reserved for national use
        (113, String::from("ans ...999")), //
        (114, String::from("ans ...999")), //
        (115, String::from("ans ...999")), //
        (116, String::from("ans ...999")), //
        (117, String::from("ans ...999")), //
        (118, String::from("ans ...999")), //
        (119, String::from("ans ...999")), //
        (120, String::from("ans ...999")), // Reserved for private use
        (121, String::from("ans ...999")), //
        (122, String::from("ans ...999")), //
        (123, String::from("ans ...999")), //
        (124, String::from("ans ...999")), //
        (125, String::from("ans ...999")), //
        (126, String::from("ans ...999")), //
        (127, String::from("ans ...999")), //
        (128, String::from("b 64")),      // Message authentication code
    ]);

    let mut iso_msg = "020042000400000000021612345678901234560609173030123401079ABC1000123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789".to_string();

    if iso_msg.len() % 2 != 0 {
        iso_msg.push_str(&"0");
    }

    let iso_msg = iso8583_parser::decode_hex(&iso_msg).unwrap(); // pad right with zero first if not enough for a byte

    let parser = iso8583_parser::Parser::new(&iso_data_elements_spec);

    let txn = parser.parse_isomsg(&iso_msg);

    println!("{:#?}", txn);

    let txn_specific = map_txn_type(txn);

    match txn_specific {
        TxnType::SaleTxn(_sale_struct) => println!("process sale txn"),
        TxnType::VoidTxn(_void_struct) => println!("process void txn"),
    }
}
