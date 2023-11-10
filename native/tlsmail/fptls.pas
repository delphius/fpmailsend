unit fptls;
{
  Simple plain program that implements PoC of TLS v1.3 in pure fpc 3.3.1+

  Inspired by [Manual TLS](https://github.com/alexbers/manual-tls)

  (c) Delphius
  
  License MIT
}
{$mode objfpc}{$H+}
interface

uses
  sysutils, fpsha256, fphashutils, sockets, resolve;

function Connect(const Host:String; const Port:Integer) : Boolean;
function ConClose : Boolean;
function Send(Const REQUESTS: String): Integer;
function Recv(var decrypted_msg: TBytes): Integer;

implementation

  var
   Debug: Boolean;
  // https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2
  // The legacy_version field MUST be set to 0x0303, which is the version number for TLS 1.2
  // In tls 1.3 the version tls 1.2 is sent for better compatibility
  const
    LEGACY_TLS_VERSION: array of Byte = ($03, $03);

  // TLS Cipher Suites
  // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
  // https://www.rfc-editor.org/rfc/rfc8446.html#appendix-B.4
  //TLS_AES_128_GCM_SHA256: array[0..1] of Byte = ($13, $01);

//**BYTE MANIPULATION HELPERS
//  Converts an array of bytes to an unsigned 32-bit integer (LongWord) in big-endian format.
function WordToBE(Buffer:TBytes):Word;
begin
 Result:= ((Buffer[0] and 255) shl 8) or (Buffer[1] and 255);
end;
//  Converts an array of bytes to an unsigned 32-bit integer (LongWord) in big-endian format.
function LongWordToBE(Buffer:PByte):LongWord;
begin
 Result:=((Buffer[0] and 255) shl 24) or ((Buffer[1] and 255) shl 16) or ((Buffer[2] and 255) shl 8) or (Buffer[3] and 255);
end;
//  Converts an unsigned 32-bit integer (LongWord) to an array of bytes with length of 4 bytes (32 bit).
procedure BEToLongWord(Value: LongWord; Buffer: PByte);
var
  i: Integer;
begin
  for i := 0 to 3 do
    Buffer[i] := Byte((Value shr (24 - i * 8)) and $FF);
end;
//  Converts an unsigned 32-bit integer (UInt32) to an array of bytes with a specified length.
function UInt32ToBytesBE(num: UInt32; bytes_len: Integer): TBytes;
var
  i: Integer;
begin
  SetLength(Result, bytes_len);
  for i := 0 to bytes_len - 1 do
    Result[i] := Byte((num shr (8 * (bytes_len - 1 - i))) and $FF);
end;
// Converts an unsigned 64-bit integer (UInt64) to an array of bytes with length of 8 bytes (64 bit).
function UInt64ToBytesBE(value: UInt64): TBytes;
var
  i: Integer;
begin
  SetLength(Result, 8);
  for i := 0 to 7 do
    Result[i] := Byte((value shr (56 - i * 8)) and $FF);
end;
// Concatenates two arrays of bytes and returns the result.
function ConcatenateBytes(const A, B: TBytes): TBytes;
begin
  SetLength(Result, Length(A) + Length(B));
  if Length(A) > 0 then Move(A[0], Result[0], Length(A));
  if Length(B) > 0 then Move(B[0], Result[Length(A)], Length(B));
end;

function SeqNumToBytes(seq: UInt32): TBytes;
var
  i: Integer;
begin
  SetLength(Result, 12);
  FillByte(Result[0], 8, 0);
  for i := 0 to 3 do
    Result[i + 8] := Byte((seq shr (8 * (3 - i))) and $FF);
end;

function XorBytes(a, b: TBytes): TBytes;
var
  i: Integer;
begin
  SetLength(Result, Length(a));

  for i := 0 to High(a) do
  begin
    Result[i] := a[i] xor b[i];
  end;
end;

//**SYMMETRIC CIPHERS
//  CHACHA20 + POLY1305

{TO DO}

// AES 128 + EXPAND KEYS
const  
  {`AES_ROUNDS` is a constant that specifies the number of rounds (iterations) in the Advanced Encryption Standard (AES) encryption algorithm.
  AES is a symmetric block cipher that uses multiple rounds to process input data and produce encrypted output.
  The AES standard defines three cipher variants with different numbers of rounds:
  - AES-128: Uses 10 rounds.
  The number of rounds affects the security and performance of the cipher.
  A higher number of rounds makes the cipher more resistant to attacks but also requires more computational resources for encryption and decryption.}
  // AES-128. The algorithm will perform 10 rounds of encryption to encrypt data.
  AES_ROUNDS = 10;
  // 128 bit blocks
  AES_BLOCK_SIZE = 16;
  // AES_SBOX is some permutation of numbers 0-255
  // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
  AES_SBOX: array[0..255] of Byte = (99, 124, 119, 123, 242, 107, 111, 197, 48, 1,
      103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173,
      212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204,
      52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7,
      18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59,
      214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203,
      190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2,
      127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218,
      33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126,
      61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184,
      20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98,
      145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244,
      234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116,
      31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185,
      134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135,
      233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45,
      15, 176, 84, 187, 22);
type
  TAESKeySchedule = array[0..AES_ROUNDS] of array[0..3] of UInt32;

function AES128ExpandKey(key: TBytes): TAESKeySchedule;
const
  RCON: array[0..9] of Byte = ($01, $02, $04, $08, $10, $20, $40, $80, $1B, $36);
var
  enc_keys: TAESKeySchedule absolute Result;
  t, i: Integer;
begin
  for t := 0 to AES_ROUNDS do
    for i := 0 to 3 do
      enc_keys[t][i] := 0;

  for i := 0 to 3 do
      begin
        //WriteLn(BytesToHexStr(Copy(key, i * 4, 4)));
        enc_keys[0][i] := LongWordToBE(PByte(Copy(key, i * 4, 4)));
        //WriteLn(BytesToHexStr(UInt32ToBytesBE(enc_keys[0][i],4)));
      end;
  for t := 1 to AES_ROUNDS do
  begin
    for i := 0 to 3 do
    begin
      enc_keys[t][i] := (AES_SBOX[(enc_keys[t-1][3] shr (8 * 2)) and $FF] shl (8 * 3)) xor
                       (AES_SBOX[(enc_keys[t-1][3] shr (8 * 1)) and $FF] shl (8 * 2)) xor
                       (AES_SBOX[(enc_keys[t-1][3] shr (8 * 0)) and $FF] shl (8 * 1)) xor
                       (AES_SBOX[(enc_keys[t-1][3] shr (8 * 3)) and $FF] shl (8 * 0)) xor
                       (RCON[t-1] shl (8 * 3)) xor enc_keys[t-1][0];
    end;

    for i := 1 to 3 do
      enc_keys[t][i] := enc_keys[t][i-1] xor enc_keys[t-1][i];
  end;
end;

function AES128Encrypt(key, plaintext: TBytes): TBytes;
type
  AESColumn=UInt32;
  FourBytes=array[0..3] of byte;
var
  enc_keys: TAESKeySchedule;
  round,i:byte;
  State, MixBase:array[0..3] of UInt32;

function GMul4(a:AESColumn;b:byte):AESColumn;
var
  c:AESColumn absolute Result;
  i:byte;
begin
  c:=a * AESColumn(b and 1);
  for i:=1 to 7 do
   begin
    a:=((a and $7F7F7F7F) shl 1) xor ($1b * ((a and $80808080) shr 7));
    b:=b shr 1;
    c:=c xor (a * (b and 1));
   end;
end;

begin
  enc_keys := AES128ExpandKey(key);
  for round:=0 to 10 do
    for i:=0 to 3 do
      enc_keys[Round][i] := NtoBE(enc_keys[Round][i]);

  for i := 0 to 3 do
    State[i] := NtoBE(LongWordToBE(PByte(Copy(plaintext, i * 4, 4))));
  //AddRoundKey
  for i:=0 to 3 do
    State[i]:=State[i] xor enc_keys[0][i];

  for round:=1 to 10 do
   begin
    //SubBytes+ShiftRows
    for i:=0 to 3 do
     begin
      FourBytes(MixBase[i])[0]:=AES_SBOX[FourBytes(State[ i         ])[0]];
      FourBytes(MixBase[i])[1]:=AES_SBOX[FourBytes(State[(i+1) and 3])[1]];
      FourBytes(MixBase[i])[2]:=AES_SBOX[FourBytes(State[(i+2) and 3])[2]];
      FourBytes(MixBase[i])[3]:=AES_SBOX[FourBytes(State[(i+3) and 3])[3]];
     end;
    //MixColumns
    if round=10 then
      State:=MixBase
    else
      for i:=0 to 3 do
        State[i]:=
          GMul4(MixBase[i],2) xor
          GMul4((MixBase[i] shr 8) or (MixBase[i] shl 24),3) xor
          ((MixBase[i] shr 16) or (MixBase[i] shl 16)) xor
          ((MixBase[i] shr 24) or (MixBase[i] shl 8));
    //AddRoundKey
    for i:=0 to 3 do
      State[i]:=State[i] xor enc_keys[Round][i];
   end;
  SetLength(Result, 16);
  for i := 0 to 3 do
      begin
        Move(State[i], Result[i * 4], 4);
        //WriteLn(State[i]);
        //WriteLn(BytesToHexStr(UInt32ToBytesBE(State[i], 4)));
        //WriteLn(BytesToHexStr(Result));
      end;
end;

//  AES COUNTER MODE
function aes128_ctr_encrypt(key, msg, nonce: TBytes; counter_start_val: UInt32): TBytes;
const
  BLOCK_SIZE = 16;
var
  ans: TBytes absolute Result;
  counter: UInt32;
  s, i: Integer;
  chunk, chunk_nonce, encrypted_chunk_nonce, decrypted_chunk: TBytes;
begin
  SetLength(ans, 0);
  counter := counter_start_val;
  s := 0;
  while s < Length(msg) do
  begin
    if Length(msg) - s >= BLOCK_SIZE
      then
        begin
          SetLength(chunk, BLOCK_SIZE);
          Move(msg[s], chunk[0], BLOCK_SIZE);
        end
      else
        begin
          SetLength(chunk, Length(msg) - s);
          Move(msg[s], chunk[0], Length(msg) - s);
        end;
    SetLength(chunk_nonce, Length(nonce) + 4);
    Move(nonce[0], chunk_nonce[0], Length(nonce));
    Move(UInt32ToBytesBE(counter, 4)[0], chunk_nonce[Length(nonce)], 4);
    encrypted_chunk_nonce := AES128Encrypt(key, chunk_nonce);
    SetLength(decrypted_chunk, Length(chunk));
    for i := 0 to High(chunk) do
      decrypted_chunk[i] := chunk[i] xor encrypted_chunk_nonce[i];
    SetLength(Ans, Length(Ans) + Length(decrypted_chunk));
    Move(decrypted_chunk[0], Ans[Length(Ans) - Length(decrypted_chunk)], Length(decrypted_chunk));
    counter := counter + 1;
    s := s + BLOCK_SIZE;
  end;
end;

function aes128_ctr_decrypt(key, msg, nonce: TBytes; counter_start_val: UInt32): TBytes;
begin
  Result := aes128_ctr_encrypt(key, msg, nonce, counter_start_val);
end;

//  GCM GHASH
procedure GCMXORBlock(Dest: PByte; const Source: PByte);
var
  D, S: PLongWord;
  i: Integer;
begin
  D := PLongWord(Dest);
  S := PLongWord(Source);
  for i := 1 to 4 do
  begin
    D^ := D^ xor S^;
    Inc(D);
    Inc(S);
  end;
end;

procedure GCMShiftRightBlock(V:PByte);
var
 Value:LongWord;
begin
 Value:=LongWordToBE(PByte(PtrUInt(PtrUInt(V) + 12)));
 Value:=Value shr 1;
 if (V[11] and $01) <> 0 then
  begin
   Value:=Value or $80000000;
  end;
 BEToLongWord(Value,PByte(PtrUInt(PtrUInt(V) + 12)));

 Value:=LongWordToBE(PByte(PtrUInt(PtrUInt(V) + 8)));
 Value:=Value shr 1;
 if (V[7] and $01) <> 0 then
  begin
   Value:=Value or $80000000;
  end;
 BEToLongWord(Value,PByte(PtrUInt(PtrUInt(V) + 8)));

 Value:=LongWordToBE(PByte(PtrUInt(PtrUInt(V) + 4)));
 Value:=Value shr 1;
 if (V[3] and $01) <> 0 then
  begin
   Value:=Value or $80000000;
  end;
 BEToLongWord(Value,PByte(PtrUInt(PtrUInt(V) + 4)));

 Value:=LongWordToBE(V);
 Value:=Value shr 1;
 BEToLongWord(Value,V);
end;

procedure GCMGFMult(const X,Y:PByte;Z:PByte);
var
 i, j:Integer;
 V:array[0..AES_BLOCK_SIZE - 1] of Byte;
begin
 FillChar(Z^,AES_BLOCK_SIZE,0);
 System.Move(Y^,V,AES_BLOCK_SIZE);
 for i := 0 to AES_BLOCK_SIZE - 1 do
  begin
   for j := 0 to 7 do
    begin
     if (X[i] and (1 shl (7 - j))) <> 0 then
       GCMXORBlock(Z,@V);

     if (V[15] and $01) <> 0 then
      begin
       GCMShiftRightBlock(@V);
       V[0]:=V[0] xor $e1;
      end
     else
       GCMShiftRightBlock(@V);
    end;
  end;
end;

procedure GCMGHash(const H,X:PByte;XSize:PtrUInt;Y:PByte);
var
 I:Integer;
 M:PtrUInt;
 Last:PtrUInt;
 Temp:array[0..AES_BLOCK_SIZE - 1] of Byte;
 XPos:PByte;
begin
 FillChar(Y^,AES_BLOCK_SIZE,0);
 M:=XSize div 16;
 if M < 1 then M := 1;
 XPos:=X;
 for I := 0 to M - 1 do
  begin
   GCMXORBlock(Y,XPos);
   Inc(XPos,AES_BLOCK_SIZE);
   GCMGFMult(Y,H,@Temp);
   System.Move(Temp,Y^,AES_BLOCK_SIZE);
  end;
 if (PtrUInt(X) + XSize) > PtrUInt(XPos) then
  begin
   Last:=(PtrUInt(X) + XSize) - PtrUInt(XPos);
   System.Move(XPos^,Temp,Last);
   FillChar(Pointer(PtrUInt(@Temp) + Last)^,AES_BLOCK_SIZE - Last,0);
   GCMXORBlock(Y,@Temp);
   GCMGFMult(Y,H,@Temp);
   System.Move(Temp,Y^,AES_BLOCK_SIZE);
  end;
end;

//  GALOIS COUNTER MODE
function calc_pretag(key: TBytes; encrypted_msg, associated_data: TBytes): TBytes;
const
  BLOCK_SIZE = 16;
var
  v, u, h: TBytes;
  data: TBytes;
begin
  SetLength(v, BLOCK_SIZE * ((Length(associated_data) + BLOCK_SIZE - 1) div BLOCK_SIZE) - Length(associated_data));
  SetLength(u, BLOCK_SIZE * ((Length(encrypted_msg) + BLOCK_SIZE - 1) div BLOCK_SIZE) - Length(encrypted_msg));
  h := AES128Encrypt(key, TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
  SetLength(data, Length(associated_data) + Length(v) + Length(encrypted_msg) + Length(u) + 8 + 8);
  Move(associated_data[0], data[0], Length(associated_data));
  Move(v[0], data[Length(associated_data)], Length(v));
  Move(encrypted_msg[0], data[Length(associated_data) + Length(v)], Length(encrypted_msg));
  if Length(u) > 0 then Move(u[0], data[Length(associated_data) + Length(v) + Length(encrypted_msg)], Length(u));
  Move(UInt64ToBytesBE(Length(associated_data) * 8)[0], data[Length(associated_data) + Length(v) + Length(encrypted_msg) + Length(u)], 8);
  Move(UInt64ToBytesBE(Length(encrypted_msg) * 8)[0], data[Length(associated_data) + Length(v) + Length(encrypted_msg) + Length(u) + 8], 8);
  SetLength(Result, 16);
  GCMGHash(PByte(h), PByte(data), Length(data), PByte(Result));
end;

function aes128_gcm_decrypt(key, msg, nonce, associated_data: TBytes): TBytes;
const
  TAG_LEN = 16;
  COUNTER_START_VAL = 1;
var
  encrypted_msg, tag, pretag, check_tag: TBytes;
  i: Integer;
  decryption_error: Boolean;
begin
  SetLength(encrypted_msg, Length(msg) - TAG_LEN);
  SetLength(tag, TAG_LEN);
  for i := 0 to Length(encrypted_msg) - 1 do
    encrypted_msg[i] := msg[i];
  for i := 0 to TAG_LEN - 1 do
    tag[i] := msg[Length(msg) - TAG_LEN + i];
  pretag := calc_pretag(key, encrypted_msg, associated_data);
  check_tag := aes128_ctr_encrypt(key, pretag, nonce, COUNTER_START_VAL);
  decryption_error := False;
  for i := 0 to TAG_LEN - 1 do
  begin
    if check_tag[i] <> tag[i] then
    begin
      decryption_error := True;
      Break;
    end;
  end;
  if decryption_error then
    begin
      WriteLn('Decrypt error, bad tag');
      Halt(1);
    end;
  Result := aes128_ctr_decrypt(key, encrypted_msg, nonce, COUNTER_START_VAL + 1);
end;

function aes128_gcm_encrypt(key, msg, nonce, associated_data: TBytes): TBytes;
const
  COUNTER_START_VAL1 = 1;
  COUNTER_START_VAL2 = 2;
var
  encrypted_msg, pretag, tag, res: TBytes;
  i: Integer;
begin
  encrypted_msg := aes128_ctr_encrypt(key, msg, nonce, COUNTER_START_VAL2);
  pretag := calc_pretag(key, encrypted_msg, associated_data);
  tag := aes128_ctr_encrypt(key, pretag, nonce, COUNTER_START_VAL1);
  SetLength(res, Length(encrypted_msg) + Length(tag));
  for i := 0 to Length(encrypted_msg) - 1 do
    res[i] := encrypted_msg[i];
  for i := 0 to Length(tag) - 1 do
    res[Length(encrypted_msg) + i] := tag[i];
  Result := res;
end;

function do_authenticated_encryption(key, nonce_base: TBytes; seq_num: integer; msg_type, payload: TBytes): TBytes;
const
  TAG_LEN = 16;
var
  nonce, seq_num_bytes, data: TBytes;
begin
  payload := ConcatenateBytes(payload, msg_type);
  seq_num_bytes := SeqNumToBytes(seq_num);
  nonce := XorBytes(nonce_base, seq_num_bytes);
  data := [
    $17, //APPLICATION_DATA
    $03, $03, //LEGACY_TLS_VERSION
    Byte((Length(payload) + TAG_LEN) shr 8), Byte((Length(payload) + TAG_LEN) and $FF)
  ];
  Result := aes128_gcm_encrypt(key, payload, nonce, data);
end;

//**ELLIPTIC CURVE FUNCTIONS
//  curve25519
type
  TGF = array[0..15] of Int64;
  PGF = ^TGF;

procedure Set25519(r, a: PGF);
var
  i: Integer;
begin
  for i := 0 to 15 do
    r^[i] := a^[i];
end;

procedure car25519(o: pgf);
var
  i: integer;
begin
  for i := 0 to 15 do begin
    o^[(i+1) mod 16] += (1 + 37 * Integer(i = 15)) * SarInt64(o^[i], 16); // ifthen(i = 15, 38, 1)
    o^[i] := o^[i] and $FFFF;
  end;
end;

procedure Sel25519(p, q: PGF; b: Integer);
var
  i: Integer;
  t, c: Int64;
begin
  c := not (b - 1);
  for i := 0 to 15 do
  begin
    t := c and (p^[i] xor q^[i]);
    p^[i] := p^[i] xor t;
    q^[i] := q^[i] xor t;
  end;
end;

procedure Pack25519(o: PByte; n: PGF);
var
  i, j, b: Integer;
  m: TGF;
begin
  Car25519(n);
  Car25519(n);
  Car25519(n);
  for j := 0 to 1 do
  begin
    m[0] := n^[0] - $FFED;
    for i := 1 to 14 do
    begin
      m[i] := n^[i] - $FFFF - ((m[i - 1] shr 16) and 1);
      m[i - 1] := m[i - 1] and $FFFF;
    end;
    m[15] := n^[15] - $7FFF - ((m[14] shr 16) and 1);
    b := (m[15] shr 16) and 1;
    m[14] := m[14] and $FFFF;
    Sel25519(n, @m, 1-b);
  end;
  for i := 0 to 15 do
  begin
    o[2 * i] := Byte(n^[i] and $FF);
    o[2 * i + 1] := Byte(n^[i] shr 8);
  end;
end;

procedure Unpack25519(o: PGF; const n: PByte);
var
  i: Integer;
begin
  for i := 0 to 15 do
    o^[i] := n[2 * i] + int64(n[2 * i + 1]) shl 8;
  o^[15] := o^[15] and $7FFF;
end;

procedure AA(o, a, b: PGF);
var
  i: Integer;
begin
  for i := 0 to 15 do
    o^[i] := a^[i] + b^[i];
end;

procedure ZZ(o, a, b: PGF);
var
  i: Integer;
begin
  for i := 0 to 15 do
    o^[i] := a^[i] - b^[i];
end;

procedure M(o, a, b: PGF);
var
  i, j: Integer;
  t: array[0..30] of Int64;
begin
  for i := 0 to 30 do
    t[i] := 0;
  for i := 0 to 15 do
    for j := 0 to 15 do
      t[i + j] := t[i + j] + a^[i] * b^[j];
  for i := 0 to 14 do
    t[i] := t[i] + 38 * t[i + 16];
  for i := 0 to 15 do
    o^[i] := t[i];
  Car25519(o);
  Car25519(o);
end;

procedure S(o, a: PGF);
begin
  M(o, a, a);
end;

procedure Inv25519(o, i: PGF);
var
  c: TGF;
  a: Integer;
begin
  Set25519(@c, i);
  for a := 253 downto 0 do
  begin
    S(@c, @c);
    if (a <> 2) and (a <> 4) then
      M(@c, @c, i);
  end;
  Set25519(o, @c);
end;

procedure CryptoScalarmult(q, n, p: PByte);
var
  z: array[0..31] of Byte;
  i, r: Integer;
  x, a, b, c, d, e, f: TGF;
const
  _121665: TGF = ($DB41, $1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
begin
  for i := 0 to 30 do
    z[i] := n[i];
  z[31] := (n[31] and 127) or 64;
  z[0] := z[0] and $F8;
  Unpack25519(@x, p);
  for i := 0 to 15 do
  begin
    b[i] := x[i];
    d[i] := 0;
    a[i] := 0;
    c[i] := 0;
  end;
  a[0] := 1;
  d[0] := 1;
 
  for i := 254 downto 0 do
  begin
    r := (z[i shr 3] shr (i and 7)) and 1;
    Sel25519(@a, @b, r);
    Sel25519(@c, @d, r);
    AA(@e, @a, @c);
    ZZ(@a, @a, @c);
    AA(@c, @b, @d);
    ZZ(@b, @b, @d);
    S(@d, @e);
    S(@f, @a);
    M(@a, @c, @a);
    M(@c, @b, @e);
    AA(@e, @a, @c);
    ZZ(@a, @a, @c);
    S(@b, @a);
    ZZ(@c, @d, @f);
    M(@a, @c, @_121665);
    AA(@a, @a, @d);
    M(@c, @c, @a);
    M(@a, @d, @f);
    M(@d, @b, @x);
    S(@b, @e);
    Sel25519(@a, @b, r);
    Sel25519(@c, @d, r);
  end;
  Inv25519(@c, @c);
  M(@a, @a, @c);
  Pack25519(q, @a);
end;

procedure CryptoScalarmultBase(q, n: PByte);
const
_9: array[0..31] of Byte = (9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
begin
  CryptoScalarmult(q, n, _9);
end;

//**HKDF FUNCTIONS
function DeriveSecret(const lbel_string: String; key, data: TBytes; hashLen: Integer): TBytes;
const
  TLS13_LABEL_PREFIX: array[0..5] of Byte = ($74, $6C, $73, $31, $33, $20);
var
  lbel, fullLabel, packedData, sum, secret: TBytes;
  secret_str: String;
  i: Integer;
begin
  lbel := HexStrToBytes(StringToHex(lbel_string));
  SetLength(fullLabel, Length(lbel) + 6);
  for i := 0 to 5 do
    fullLabel[i] := TLS13_LABEL_PREFIX[i];
  for i := 0 to Length(lbel) - 1 do
    fullLabel[i + 6] := lbel[i];
  SetLength(packedData, 2 + 1 + Length(fullLabel) + 1 + Length(data));
  packedData[0] := Byte(hashLen shr 8);
  packedData[1] := Byte(hashLen);
  packedData[2] := Byte(Length(fullLabel));
  for i := 0 to Length(fullLabel) - 1 do
    packedData[i + 3] := fullLabel[i];
  packedData[3 + Length(fullLabel)] := Byte(Length(data));
  for i := 0 to Length(data) - 1 do
    packedData[i + 4 + Length(fullLabel)] := data[i];
  SetLength(secret, 0);
  sum := packedData;
  SetLength(sum, Length(packedData)+1);
  i := 1;
  while Length(secret) < hashLen do
  begin
    sum[Length(packedData)] := Byte(i);
    TSHA256.HMACHexa(key, ConcatenateBytes(secret, sum), secret_str);
    secret := HexStrToBytes(secret_str);
    Inc(i);
  end;
  SetLength(Result, hashLen);
  for i := 0 to hashLen - 1 do
    Result[i] := secret[i];
end;

function GenClientHello(clientRandom, ecdhPubKeyX: TBytes; const host: String): TBytes;
const
  CLIENT_HELLO: TBytes = ($01);
  TLS_AES_128_GCM_SHA256: TBytes = ($13, $01);
var
  sessionID, compressionMethod, supportedVersions, supportedVersionsLength, anotherSupportedVersionsLength,
  tls13Version, supportedVersionExtension, signatureAlgos, signatureAlgosLength, anotherSignatureAlgosLength, rsaPssRsaeSha256Algo,
  signatureAlgosExtension, supportedGroups, supportedGroupsLength, anotherSupportedGroupsLength, secp256r1Group, supportedGroupsExtension,
  ecdhPubKey, keyShare, keyShareLength, anotherKeyShareLength, keyExchangeLen, keyShareExtension, extensions, clientHelloData,
  clientHelloLenBytes, clientHelloTLV, serverName, serverNameExtention: TBytes;
  i: Integer;
begin
  sessionID := [$00];
  compressionMethod := [$00]; // no compression

  // Server Name Extention
  serverName := TEncoding.UTF8.GetBytes(host);
  serverNameExtention := [$00, $00, // assigned value for extension "server name"
                          Byte((Length(serverName) + 5) shr 8), Byte((Length(serverName) + 5) and $FF), // bytes of "server name" extension data follows
                          Byte((Length(serverName) + 3) shr 8), Byte((Length(serverName) + 3) and $FF), // bytes of first (and only) list entry follows
                          $00, //  list entry is type 0x00 "DNS hostname"
                          Byte(Length(serverName) shr 8), Byte(Length(serverName) and $FF) //bytes of hostname follows
                         ];
  serverNameExtention := ConcatenateBytes(serverNameExtention, serverName);
  WriteLn('SNI: ', BytesToHexStr(serverNameExtention));
  
  supportedVersions := [$00, $2B];
  supportedVersionsLength := [$00, $03];
  anotherSupportedVersionsLength := [$02];
  tls13Version := [$03, $04];
  SetLength(supportedVersionExtension, Length(supportedVersions) +
    Length(supportedVersionsLength) + Length(anotherSupportedVersionsLength) +
    Length(tls13Version));
  i := 0;
  Move(supportedVersions[0], supportedVersionExtension[i], Length(supportedVersions));
  Inc(i, Length(supportedVersions));
  Move(supportedVersionsLength[0], supportedVersionExtension[i], Length(supportedVersionsLength));
  Inc(i, Length(supportedVersionsLength));
  Move(anotherSupportedVersionsLength[0], supportedVersionExtension[i], Length(anotherSupportedVersionsLength));
  Inc(i, Length(anotherSupportedVersionsLength));
  Move(tls13Version[0], supportedVersionExtension[i], Length(tls13Version));

  signatureAlgos := [$00, $0D];
  signatureAlgosLength := [$00, $04];
  anotherSignatureAlgosLength := [$00, $02];
  rsaPssRsaeSha256Algo := [$08, $04];
  SetLength(signatureAlgosExtension, Length(signatureAlgos) +
    Length(signatureAlgosLength) + Length(anotherSignatureAlgosLength) +
    Length(rsaPssRsaeSha256Algo));
  i := 0;
  Move(signatureAlgos[0], signatureAlgosExtension[i], Length(signatureAlgos));
  Inc(i, Length(signatureAlgos));
  Move(signatureAlgosLength[0], signatureAlgosExtension[i], Length(signatureAlgosLength));
  Inc(i, Length(signatureAlgosLength));
  Move(anotherSignatureAlgosLength[0], signatureAlgosExtension[i], Length(anotherSignatureAlgosLength));
  Inc(i, Length(anotherSignatureAlgosLength));
  Move(rsaPssRsaeSha256Algo[0], signatureAlgosExtension[i], Length(rsaPssRsaeSha256Algo));

  supportedGroups := [$00, $0A];
  supportedGroupsLength := [$00, $04];
  anotherSupportedGroupsLength := [$00, $02];
  secp256r1Group := [$00, $1d];
  SetLength(supportedGroupsExtension, Length(supportedGroups) +
    Length(supportedGroupsLength) + Length(anotherSupportedGroupsLength) +
    Length(secp256r1Group));
  i := 0;
  Move(supportedGroups[0], supportedGroupsExtension[i], Length(supportedGroups));
  Inc(i, Length(supportedGroups));
  Move(supportedGroupsLength[0], supportedGroupsExtension[i], Length(supportedGroupsLength));
  Inc(i, Length(supportedGroupsLength));
  Move(anotherSupportedGroupsLength[0], supportedGroupsExtension[i], Length(anotherSupportedGroupsLength));
  Inc(i, Length(anotherSupportedGroupsLength));
  Move(secp256r1Group[0], supportedGroupsExtension[i], Length(secp256r1Group));

  ecdhPubKey := [$04];
  SetLength(ecdhPubKey, Length(ecdhPubKeyX));
  Move(ecdhPubKeyX[0], ecdhPubKey[0], Length(ecdhPubKeyX));

  keyShare := [$00, $33];
  keyShareLength := UInt32ToBytesBE(Length(ecdhPubKey) + 4 + 2, 2);
  anotherKeyShareLength := UInt32ToBytesBE(Length(ecdhPubKey) + 4, 2);
  keyExchangeLen := UInt32ToBytesBE(Length(ecdhPubKey), 2);
  SetLength(keyShareExtension, Length(keyShare) + Length(keyShareLength) +
    Length(anotherKeyShareLength) + Length(secp256r1Group) + Length(keyExchangeLen) +
    Length(ecdhPubKey));
  i := 0;
  Move(keyShare[0], keyShareExtension[i], Length(keyShare));
  Inc(i, Length(keyShare));
  Move(keyShareLength[0], keyShareExtension[i], Length(keyShareLength));
  Inc(i, Length(keyShareLength));
  Move(anotherKeyShareLength[0], keyShareExtension[i], Length(anotherKeyShareLength));
  Inc(i, Length(anotherKeyShareLength));
  Move(secp256r1Group[0], keyShareExtension[i], Length(secp256r1Group));
  Inc(i, Length(secp256r1Group));
  Move(keyExchangeLen[0], keyShareExtension[i], Length(keyExchangeLen));
  Inc(i, Length(keyExchangeLen));
  Move(ecdhPubKey[0], keyShareExtension[i], Length(ecdhPubKey));

  SetLength(extensions, Length(serverNameExtention) + Length(supportedVersionExtension) + Length(signatureAlgosExtension) +
    Length(supportedGroupsExtension) + Length(keyShareExtension));
  i := 0;
  Move(serverNameExtention[0], extensions[i], Length(serverNameExtention));
  Inc(i, Length(serverNameExtention));
  Move(supportedVersionExtension[0], extensions[i], Length(supportedVersionExtension));
  Inc(i, Length(supportedVersionExtension));
  Move(signatureAlgosExtension[0], extensions[i], Length(signatureAlgosExtension));
  Inc(i, Length(signatureAlgosExtension));
  Move(supportedGroupsExtension[0], extensions[i], Length(supportedGroupsExtension));
  Inc(i, Length(supportedGroupsExtension));
  Move(keyShareExtension[0], extensions[i], Length(keyShareExtension));

  SetLength(clientHelloData, 2 + Length(LEGACY_TLS_VERSION) + Length(clientRandom) +
    Length(sessionID) + Length(TLS_AES_128_GCM_SHA256) + 2 + Length(compressionMethod) + 1 +
    Length(extensions));
  i := 0;
  Move(LEGACY_TLS_VERSION[0], clientHelloData[i], Length(LEGACY_TLS_VERSION));
  Inc(i, Length(LEGACY_TLS_VERSION));
  Move(clientRandom[0], clientHelloData[i], Length(clientRandom));
  Inc(i, Length(clientRandom));
  Move(sessionID[0], clientHelloData[i], Length(sessionID));
  Inc(i, Length(sessionID));
  Move(UInt32ToBytesBE(Length(TLS_AES_128_GCM_SHA256), 2)[0], clientHelloData[i], 2);
  Inc(i, 2);
  Move(TLS_AES_128_GCM_SHA256[0], clientHelloData[i], Length(TLS_AES_128_GCM_SHA256));
  Inc(i, Length(TLS_AES_128_GCM_SHA256));
  Move(UInt32ToBytesBE(Length(compressionMethod), 1)[0], clientHelloData[i], 1);
  Inc(i, 2);
  Move(compressionMethod[0], clientHelloData[i], Length(compressionMethod));
  Inc(i, Length(compressionMethod));
  Move(UInt32ToBytesBE(Length(extensions), 1)[0], clientHelloData[i], 1);
  Inc(i, 1);
  Move(extensions[0], clientHelloData[i], Length(extensions));

  clientHelloLenBytes := UInt32ToBytesBE(Length(clientHelloData), 3);
  SetLength(clientHelloTLV, Length(CLIENT_HELLO) + Length(clientHelloLenBytes) +
    Length(clientHelloData));
  i := 0;
  Move(CLIENT_HELLO[0], clientHelloTLV[i], Length(CLIENT_HELLO));
  Inc(i, Length(CLIENT_HELLO));
  Move(clientHelloLenBytes[0], clientHelloTLV[i], Length(clientHelloLenBytes));
  Inc(i, Length(clientHelloLenBytes));
  Move(clientHelloData[0], clientHelloTLV[i], Length(clientHelloData));
  Result := clientHelloTLV;
  
  if not Debug then Exit;
  Writeln('Length is ', Length(clientHelloData), ': ', BytesToHexStr(clientHelloLenBytes));
  Writeln('Legacy client version is TLS 1.2: ', BytesToHexStr(LEGACY_TLS_VERSION));
  Writeln('Client random: ', BytesToHexStr(clientRandom));
  Writeln('Session id len is 0: ', BytesToHexStr(sessionID));
  Writeln('Session id: ', BytesToHexStr(sessionID));
  Writeln('Cipher suites len is 2: ', BytesToHexStr(UInt32ToBytesBE(Length(TLS_AES_128_GCM_SHA256), 2)));
  Writeln('Cipher suite is TLS_AES_128_GCM_SHA256: ', BytesToHexStr(TLS_AES_128_GCM_SHA256));
  Writeln('Compression method len is 1: ', BytesToHexStr(UInt32ToBytesBE(Length(compressionMethod), 1)));
  Writeln('Compression method is no compression: ', BytesToHexStr(compressionMethod));
  Writeln('Extensions len is ', Length(extensions), ': ', BytesToHexStr(UInt32ToBytesBE(Length(extensions), 2)));
  Writeln('Extension type is supported_versions: ', BytesToHexStr(supportedVersions));
  Writeln('Extension len is 3: ', BytesToHexStr(supportedVersionsLength));
  Writeln('Extension field len is 2: ', BytesToHexStr(anotherSupportedVersionsLength));
  Writeln('Version is TLS 1.3: ', BytesToHexStr(tls13Version));
  Writeln('Extension type is signature_algos: ', BytesToHexStr(signatureAlgos));
  Writeln('Extension len is 4: ', BytesToHexStr(signatureAlgosLength));
  Writeln('Extension field len is 2: ', BytesToHexStr(anotherSignatureAlgosLength));
  Writeln('Algo is rsa_pss_rsae_sha256_algo: ', BytesToHexStr(rsaPssRsaeSha256Algo));
  Writeln('Extension type is supported_groups: ', BytesToHexStr(supportedGroups));
  Writeln('Extension len is 4: ', BytesToHexStr(supportedGroupsLength));
  Writeln('Extension field len is 2: ', BytesToHexStr(anotherSupportedGroupsLength));
  Writeln('Group is secp256r1_group: ', BytesToHexStr(secp256r1Group));
  Writeln('Extension type is key_share: ', BytesToHexStr(keyShare));
  Writeln('Extension len is ', Length(keyShareLength), ': ', BytesToHexStr(keyShareLength));
  Writeln('Extension field len is ', Length(anotherKeyShareLength), ': ', BytesToHexStr(anotherKeyShareLength));
  Writeln('Key length ', Length(ecdhPubKey), ': ', BytesToHexStr(keyExchangeLen));
  Writeln('Key is: ', BytesToHexStr(ecdhPubKey));
  Writeln('Client Hello TLV: ', BytesToHexStr(clientHelloTLV));
  Writeln('Client Hello TLV len: ', Length(clientHelloTLV));
end;

function HandleFinished(Finished, Key, Msgs: TBytes): Boolean;
  var verify_data_len, i: Integer;
      verify_data, shaMsgs: TBytes;
      hmac_digest: String;
      hmac_digest_bytes: TBytes;
begin
  if Finished[0] <> $14
    then raise Exception.Create('Handshake type is not FINISHED (0x14)');
  verify_data_len := Finished[1] shl 16 or Finished[2] shl 8 or Finished[3];
  SetLength(verify_data, verify_data_len);
  Move(Finished[4], verify_data[0], verify_data_len);
  TSHA256.DigestBytes(Msgs, shaMsgs);
  TSHA256.HMACHexa(Key, shaMsgs, hmac_digest);
  hmac_digest_bytes := HexStrToBytes(hmac_digest);
  Result := True;
  for i := 0 to Length(verify_data) - 1 do
    if verify_data[i] <> hmac_digest_bytes[i] then
    begin
      Result := False;
      Break;
    end;
  if not Debug then Exit;
  WriteLn('<--Parse server Finish');
  WriteLn('Server Finished length: ', Length(Finished));
  WriteLn('Verify data Length: ', verify_data_len);
  WriteLn('Server Finish Content: ', BytesToHexStr(verify_data), #13#10 + '--------------------');
end;

function HandleServerHello(serverHello: TBytes): TBytes;
var
  serverHelloLen, serverVersion, serverRandom, sessionID, cipherSuite, extensions: TBytes;
  sessionIDLen, compressionMethod: Byte;
  publicECKey: TBytes;
  ptr, extensionType, keyExchangeLen: Integer;
  KEY_SHARE: Byte;
  extensionLength, extensionsLength: UInt32;
begin
  if Debug then WriteLn('--------------------' + #13#10 + '<--Parse server Hello');
  if Debug then WriteLn('Server Hello length: ', Length(serverHello));
  KEY_SHARE := $33;

  // Initialize variables
  ptr := 0;
  publicECKey := nil;

  // Extract data from the server hello message
  serverHelloLen := Copy(serverHello, 1, 3);
  serverVersion := Copy(serverHello, 4, 2);
  serverRandom := Copy(serverHello, 6, 32);

  sessionIDLen := serverHello[38];
  sessionID := Copy(serverHello, 39, sessionIDLen);

  cipherSuite := Copy(serverHello, 39 + sessionIDLen, 2);

  compressionMethod := serverHello[39 + sessionIDLen + 2];

  extensionsLength := (serverHello[39 + sessionIDLen + 3] shl 8) or serverHello[39 + sessionIDLen + 4];
  extensions := Copy(serverHello, 39 + sessionIDLen + 5, extensionsLength);

  // Extract public EC key if present
  while ptr < extensionsLength do
  begin
    extensionType := (extensions[ptr] shl 8) or extensions[ptr + 1];
    extensionLength := (extensions[ptr + 2] shl 8) or extensions[ptr + 3];

    if extensionType <> KEY_SHARE then
    begin
      Inc(ptr, extensionLength + 4);
      Continue;
    end;
    keyExchangeLen := (extensions[ptr + 6] shl 8) or extensions[ptr + 7];
    publicECKey := Copy(extensions, ptr + 8, keyExchangeLen);
    Break;
  end;

  if Length(publicECKey) = 0 then
    raise Exception.Create('No public ECDH key in server hello');

  // Return extracted data
  SetLength(Result, 32);
  Move(publicECKey[0], Result[0], 32);
  if not Debug then Exit;
  WriteLn('Type is the server hello: ', serverHello[0].ToHexString);
  WriteLn('Length is ', (serverHelloLen[0] shl 16) or (serverHelloLen[1] shl 8) or serverHelloLen[2], ': ', BytesToHexStr(serverHelloLen));
  WriteLn('Legacy server version is TLS 1.2: ', BytesToHexStr(serverVersion));
  WriteLn('Server random: ', BytesToHexStr(serverRandom));
  WriteLn('Session id len is ', sessionIDLen, ': ', BytesToHexStr(sessionID));
  WriteLn('Session id: ', BytesToHexStr(sessionID));
  WriteLn('Cipher suite is TLS_AES_128_GCM_SHA256: ', BytesToHexStr(cipherSuite));
  WriteLn('Compression method is no compression: ', compressionMethod);
  WriteLn('Extensions len is ', extensionsLength, ': ', BytesToHexStr(UInt32ToBytesBE(extensionsLength, 2)));
  WriteLn('Extension parsing was skipped, but public_ec_key is ', BytesToHexStr(publicECKey));
  WriteLn('--------------------');
end;


//  TLS ContentType
//  https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
type
  TRecType = (
    TLS_CHANGE_CIPHER    = $14,
    TLS_ALERT            = $15,
    TLS_HANDSHAKE        = $16,
    TLS_APPLICATION_DATA = $17,
    TLS_HEARTBEAT        = $18,
    TLS_TLS12_CID        = $19,
    TLS_ACK              = $20
  );

var
  shakey, early_secret_bytes, handshake_secret_bytes, res_bytes: TBytes;
  early_secret,handshake_secret, client_finish_val, master_secret :String;
  CSocket: TSocket;
  Address: TInetSockAddr;
  request,ServerResponce, hello_hash: TBytes;
  ClientHello, ServerHello, ClientServerHello: TBytes;
  PublicKey, ServerKey, CommonKey: TBytes;
  server_hs_secret, server_write_key, server_write_iv, server_finished_key: TBytes;
  client_hs_secret, client_write_key, client_write_iv, client_finished_key: TBytes;
  client_seq_num, server_seq_num, msg_length, pos_msg: Integer;
  rec_type: Byte;
  encrypted_extentions, server_cert, cert_verify, finished, client_finish_val_bytes, msgs_so_far,
  msgs_sha256, handshake_msg, encrypted_handshake_msg: TBytes;
  msgs_so_far_hash, premaster_secret, master_secret_bytes: TBytes;
  server_secret, client_secret: TBytes;
  encrypted_msg, decrypted_msg: TBytes;
  server_keyex, sert_request, hello_done: TBytes;
  RecType: TRecType;
  finished_flag: Boolean;
const
  ZERO_BYTES_32: TBytes = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
  PrivateKey: TBytes = (
    $77, $07, $6D, $0A, $73, $18, $A5, $7D,
    $3C, $16, $C1, $72, $51, $B2, $66, $45,
    $DF, $4C, $2F, $87, $EB, $C0, $99, $2A,
    $B1, $77, $FB, $A5, $1D, $B9, $2C, $2A
  );

function RecvNumBytes(Socket: TSocket; num: Integer): TBytes;
  var
   Buffer: array[0..65535] of Byte;
   BytesRead, BytesReadCount, count: Integer;
begin
  count := num;
  BytesReadCount := 0;
  While count > 0 do
    begin
      BytesRead := fprecv(Socket, @Buffer[BytesReadCount], count, 0);
      if BytesRead <= 0 then begin
                               WriteLn('Server terminated the connection');
                               Halt(0);
                             end; 
      BytesReadCount += BytesRead;
      count := count - BytesRead;
    end;
  SetLength(Result, num);
  Move(Buffer[0], Result[0], num);
end;

procedure RecvTLS(Socket: TSocket; out RecType: TRecType; out TLSRec: TBytes);
var
  TLSVersion, RecLenB: TBytes;
  RecTypeB: Byte;
  RecLen: Integer;
begin
  RecTypeB := RecvNumBytes(Socket, 1)[0];
  RecType := TRecType(RecTypeB);
  TLSVersion := RecvNumBytes(Socket, 2);
  if (TLSVersion[0] <> LEGACY_TLS_VERSION[0]) or
     (TLSVersion[1] <> LEGACY_TLS_VERSION[1]) then
       raise Exception.Create('TLS version ' + BytesToHexStr(TLSVersion) + ' not supported');
  RecLenB := RecvNumBytes(Socket, 2);
  RecLen := WordToBE(RecLenB);
  TLSRec := RecvNumBytes(Socket, RecLen);
  if not Debug then Exit;
  WriteLn('--------------------' + #13#10 + '<--Recive TLS');
  WriteLn('Record Type: ', RecType, ' (0x', IntToHex(Byte(RecType)), ')');
  WriteLn('Record Length: ', RecLen, ' (0x', BytesToHexStr(RecLenB),')');
  WriteLn('Record Content: ', BytesToHexStr(TLSRec), #13#10 + '--------------------');
end;

function SendTLS(Socket: TSocket; RecType: TRecType; TLSMsg: TBytes): Boolean;
var
   tls_record: TBytes;
begin
  Result := False;
  tls_record := [
    Byte(RecType),
    $03, $03,
    Byte(Length(TLSMsg) shr 8), Byte(Length(TLSMsg) and $FF)
  ];
  tls_record := ConcatenateBytes(tls_record, TLSMsg);
  if fpsend(Socket, PByte(tls_record), longword(Length(tls_record)), 0) = 0 then
    Result := True;
  if not Debug then Exit;
  WriteLn('--------------------' + #13#10 + '-->Send TLS');
  WriteLn('Record Type: ', RecType, ' (0x', IntToHex(Byte(RecType)), ')');
  Writeln('Record Length: ' + IntToStr(Length(tls_record)) + ' (0x' + IntToHex(Length(tls_record)) + ')' + #13#10
        + 'Record Content: ' + BytesToHexStr(tls_record) + #13#10 + '--------------------');
end;

procedure RecvTLSandDecrypt(Socket: TSocket; const key, nonce: TBytes; seq_num: integer; out rec_type: byte; out TLSRec: TBytes);
var RecType: TRecType;
    TLSEncRec, TLSDecRec :TBytes;
    seq_num_bytes, xor_nonce: TBytes;
    data: TBytes;

begin
  RecvTLS(Socket, RecType, TLSEncRec);

  // For middlebox and proxy compatibility, TLS 1.3 MAY includes the now irrelevant Change Cipher Spec message.
  // From this point on, everything else from the server is encrypted and has type Application data.
  if RecType = TLS_CHANGE_CIPHER then begin
                                        WriteLn('Received a change cipher msg. ');
                                        WriteLn('--------------------');
                                        RecvTLS(Socket, RecType, TLSEncRec);
                                      end;
  if RecType <> TLS_APPLICATION_DATA
    then raise Exception.Create('TLS record type is not TLS_APPLICATION_DATA');
  seq_num_bytes := SeqNumToBytes(seq_num);
  xor_nonce := XorBytes(nonce, seq_num_bytes);
  data := [
    $17, //APPLICATION_DATA
    $03, $03, //LEGACY_TLS_VERSION
    Byte(Length(TLSEncRec) shr 8), Byte(Length(TLSEncRec) and $FF)
  ];
  TLSDecRec := aes128_gcm_decrypt(key, TLSEncRec, xor_nonce, data);
  rec_type := TLSDecRec[Length(TLSDecRec) - 1];
  SetLength(TLSRec, Length(TLSDecRec) - 1);
  Move(TLSDecRec[0], TLSRec[0], Length(TLSDecRec) - 1);
end;

// Socket connection to provided Host:Port
function ConnectTLS(var CSocket: TSocket; const Host: String; const Port: Integer): Boolean;
var
  hrs: THostResolver;
  IpAddress: String;
begin
  Result := False;
  if Debug then WriteLn('--------------------' + #13#10 + '-->Connecting to server');
  CSocket := fpsocket(AF_INET, SOCK_STREAM, 0);
  if CSocket = -1 then
    raise Exception.Create('Error creating socket.');
  hrs := THostResolver.Create(nil);
  if hrs.NameLookup(Host) then
    IpAddress := hrs.AddressAsString
  else
    raise Exception.Create('Failed to resolve the hostname: ' + Host);
  with Address do
   begin
      sin_family := AF_INET;
      sin_port:= htons(word(Port));
      sin_addr:=StrToNetAddr(hrs.AddressAsString);
   end;
  hrs.Free;
  if fpconnect(CSocket, @Address, SizeOf(Address)) < 0 then
    raise Exception.Create('Error connecting to server.');
  Result := True;
  if not Debug then Exit;
  WriteLn('Server hostname: ', Host);
  WriteLn('Resolved IP Address: ', IpAddress);
  WriteLn('Connected to server.');
  WriteLn('--------------------');
end;

function Connect(const Host:String; const Port:Integer) : Boolean;
begin
  Debug := True;
  ConnectTLS(CSocket, Host, Port);
  WriteLn('Generating params for a client hello, the first message of TLS handshake');
  SetLength(PublicKey,32);
  CryptoScalarmultBase(@PublicKey[0], @PrivateKey[0]);
  WriteLn('Our curve25519 private key: ', BytesToHexStr(PrivateKey));
  WriteLn('Our curve25519 public key: ', BytesToHexStr(PublicKey));
  request := GenClientHello(HexStrToBytes('abababababababababababababababababababababababababababababababab'), PublicKey, host);
  SendTLS(CSocket, TLS_HANDSHAKE, request);
  RecvTLS(CSocket, RecType, ServerResponce);
  ClientHello := request;
  ServerHello := ServerResponce;
  ServerKey := HandleServerHello(ServerResponce);
  SetLength(CommonKey,32);
  CryptoScalarmult(@CommonKey[0], @PrivateKey[0], @ServerKey[0]);
  WriteLn('Our curve25519 common key: ', BytesToHexStr(CommonKey), ', deriving keys');
  TSHA256.HMACHexa(TBytes([$00]), ZERO_BYTES_32, early_secret);
  WriteLn('Early secret: ', early_secret);
  early_secret_bytes := HexStrToBytes(early_secret);
  TSHA256.DigestBytes(TEncoding.UTF8.GetBytes(''), shakey);
  WriteLn('SHA256(``):   ', BytesToHexStr(shakey));
  res_bytes := DeriveSecret('derived', early_secret_bytes, shakey, 32);
  WriteLn('Preextractsec: ', BytesToHexStr(res_bytes));
  TSHA256.HMACHexa(res_bytes, CommonKey, handshake_secret);
  WriteLn('Handshakesec: ', handshake_secret);
  handshake_secret_bytes := HexStrToBytes(handshake_secret);
  SetLength(ClientServerHello, Length(ClientHello) + Length(ServerHello));
  WriteLn('Len SerCliHello = ', Length(ClientHello) + Length(ServerHello));
  Move(ClientHello[0], ClientServerHello[0], Length(ClientHello));
  Move(ServerHello[0], ClientServerHello[Length(ClientHello)], Length(ServerHello));
  WriteLn(BytesToHexStr(ClientServerHello));
  TSHA256.DigestBytes(ClientServerHello, hello_hash);
  WriteLn('Hello hash: ', BytesToHexStr(hello_hash));
  server_hs_secret := DeriveSecret('s hs traffic', handshake_secret_bytes, hello_hash, 32);
  WriteLn('Client hs secret: ', BytesToHexStr(server_hs_secret));
  server_write_key := DeriveSecret('key', server_hs_secret, TEncoding.UTF8.GetBytes(''), 16);
  WriteLn('Server write key: ', BytesToHexStr(server_write_key));
  server_write_iv := DeriveSecret('iv', server_hs_secret, TEncoding.UTF8.GetBytes(''), 12);
  WriteLn('Server write iv: ', BytesToHexStr(server_write_iv));
  server_finished_key := DeriveSecret('finished', server_hs_secret, TEncoding.UTF8.GetBytes(''), 32);
  WriteLn('Server finished key: ', BytesToHexStr(server_finished_key));
  
  client_hs_secret := DeriveSecret('c hs traffic', handshake_secret_bytes, hello_hash, 32);
  WriteLn('Client hs secret: ', BytesToHexStr(client_hs_secret));
  client_write_key := DeriveSecret('key', client_hs_secret, TEncoding.UTF8.GetBytes(''), 16);
  WriteLn('Client write key: ', BytesToHexStr(client_write_key));
  client_write_iv := DeriveSecret('iv', client_hs_secret, TEncoding.UTF8.GetBytes(''), 12);
  WriteLn('Client write iv: ', BytesToHexStr(client_write_iv));
  client_finished_key := DeriveSecret('finished', client_hs_secret, TEncoding.UTF8.GetBytes(''), 32);
  WriteLn('Client finished key: ', BytesToHexStr(client_finished_key));

  client_seq_num := 0; //for use in authenticated encryption
  server_seq_num := 0;

  msgs_so_far := ClientServerHello;
  finished_flag := False;

  repeat
  WriteLn('--------------------');
  WriteLn('Receiving and derypt message');
  RecvTLSandDecrypt(CSocket, server_write_key, server_write_iv, server_seq_num, rec_type, decrypted_msg);
  WriteLn('Record Type: ', TRecType(rec_type), ' (0x', IntToHex(Byte(rec_type)), ')');
  WriteLn('Decrypted message length: ',Length(decrypted_msg), ', parsing messages...');

  pos_msg := 0;

  while pos_msg < Length(decrypted_msg) do
    begin
      WriteLn('--------------------');
      case decrypted_msg[pos_msg] of
        $08: begin
               WriteLn('Parsing Encrypted extensions');
               msg_length := decrypted_msg[pos_msg + 1] shl 16 + decrypted_msg[pos_msg + 2] shl 8 + decrypted_msg[pos_msg + 3] and $FF;
               WriteLn('Length: ', msg_length);
               encrypted_extentions := copy(decrypted_msg, pos_msg, 4 + msg_length);
               msgs_so_far := ConcatenateBytes(msgs_so_far, encrypted_extentions);
               WriteLn('Message: ', BytesToHexStr(encrypted_extentions));
               pos_msg += 4 + msg_length;
             end;
        $0b: begin
               WriteLn('Parsing Certificate');
               msg_length := decrypted_msg[pos_msg + 1] shl 16 + decrypted_msg[pos_msg + 2] shl 8 + decrypted_msg[pos_msg + 3] and $FF;
               WriteLn('Length: ', msg_length);
               server_cert := copy(decrypted_msg, pos_msg, 4 + msg_length);
               msgs_so_far := ConcatenateBytes(msgs_so_far, server_cert);
               WriteLn('Message: ', BytesToHexStr(server_cert));
               pos_msg += 4 + msg_length;
             end;
        $0c: begin
               WriteLn('Parsing Server key exchange');
               msg_length := decrypted_msg[pos_msg + 1] shl 16 + decrypted_msg[pos_msg + 2] shl 8 + decrypted_msg[pos_msg + 3] and $FF;
               WriteLn('Length: ', msg_length);
               server_keyex := copy(decrypted_msg, pos_msg, 4 + msg_length);
               msgs_so_far := ConcatenateBytes(msgs_so_far, server_keyex);
               WriteLn('Message: ', BytesToHexStr(server_keyex));
               pos_msg += 4 + msg_length;
             end;
        $0d: begin
               WriteLn('Parsing Certificate request');
               msg_length := decrypted_msg[pos_msg + 1] shl 16 + decrypted_msg[pos_msg + 2] shl 8 + decrypted_msg[pos_msg + 3] and $FF;
               WriteLn('Length: ', msg_length);
               sert_request := copy(decrypted_msg, pos_msg, 4 + msg_length);
               msgs_so_far := ConcatenateBytes(msgs_so_far, sert_request);
               WriteLn('Message: ', BytesToHexStr(sert_request));
               pos_msg += 4 + msg_length;
             end;
        $0e: begin
               WriteLn('Parsing Server hello done');
               msg_length := decrypted_msg[pos_msg + 1] shl 16 + decrypted_msg[pos_msg + 2] shl 8 + decrypted_msg[pos_msg + 3] and $FF;
               WriteLn('Length: ', msg_length);
               hello_done := copy(decrypted_msg, pos_msg, 4 + msg_length);
               msgs_so_far := ConcatenateBytes(msgs_so_far, hello_done);
               WriteLn('Message: ', BytesToHexStr(hello_done));
               pos_msg += 4 + msg_length;
             end;
        $0f: begin
              WriteLn('Parsing Certificate verify');
              msg_length := decrypted_msg[pos_msg + 1] shl 16 + decrypted_msg[pos_msg + 2] shl 8 + decrypted_msg[pos_msg + 3] and $FF;
              WriteLn('Length: ', msg_length);
              cert_verify := copy(decrypted_msg, pos_msg, 4 + msg_length);
              msgs_so_far := ConcatenateBytes(msgs_so_far, cert_verify);
              WriteLn('Message: ', BytesToHexStr(cert_verify));
              pos_msg += 4 + msg_length;
             end;
        $10: begin
              WriteLn('Parsing Client key exchange');
             end;
        $14: begin
              WriteLn('Parsing Finish');
              msg_length := decrypted_msg[pos_msg + 1] shl 16 + decrypted_msg[pos_msg + 2] shl 8 + decrypted_msg[pos_msg + 3] and $FF;
              WriteLn('Length: ', msg_length);
              finished := copy(decrypted_msg, pos_msg, 4 + msg_length);
              WriteLn('Message: ', BytesToHexStr(finished));
              pos_msg += 4 + msg_length;
              if HandleFinished(finished, server_finished_key, msgs_so_far)
                then WriteLn('Server sent VALID finish handshake msg')
                else WriteLn('Warning: Server sent WRONG handshake finished msg');
              msgs_so_far := ConcatenateBytes(msgs_so_far, finished);
              finished_flag := true;
             end
        else raise Exception.Create('Parsing Unknown message: (0x' + IntToHex(decrypted_msg[pos_msg]) + ')');
        end;
    end;

  server_seq_num += 1;
  until finished_flag;
  
  WriteLn('--------------------');
  WriteLn('Handshake: sending a change cipher msg');
  SendTLS(CSocket, TLS_CHANGE_CIPHER, TBytes([$01]));

  //All client messages beyond this point are encrypted
  //msgs_so_far := ConcatenateBytes(msgs_so_far, finished);
  TSHA256.DigestBytes(msgs_so_far, msgs_sha256);
  TSHA256.HMACHexa(client_finished_key, msgs_sha256, client_finish_val);
  client_finish_val_bytes := HexStrToBytes(client_finish_val);

  WriteLn('Handshake: sending an encrypted finished msg');
  WriteLn('Client finish value: ', client_finish_val);
  handshake_msg := [
    $14, //FINISHED
    Byte(Length(client_finish_val_bytes) shr 16), Byte(Length(client_finish_val_bytes) shr 8), Byte(Length(client_finish_val_bytes) and $FF)
  ];
  encrypted_handshake_msg := do_authenticated_encryption(client_write_key, client_write_iv, client_seq_num,
                                                         TBytes([$16]),
                                                         ConcatenateBytes(handshake_msg, client_finish_val_bytes));
  SendTLS(CSocket, TLS_APPLICATION_DATA, encrypted_handshake_msg);

  client_seq_num += 1;
  WriteLn('Handshake finished, regenerating secrets for application data');

  //  Rederive application secrets
  TSHA256.DigestBytes(msgs_so_far , msgs_so_far_hash);
  premaster_secret := DeriveSecret('derived', handshake_secret_bytes, shakey, 32);
  TSHA256.HMACHexa(premaster_secret, ZERO_BYTES_32, master_secret);
  master_secret_bytes := HexStrToBytes(master_secret);

  server_secret := DeriveSecret('s ap traffic', master_secret_bytes, msgs_so_far_hash, 32);
  server_write_key := DeriveSecret('key', server_secret,  TEncoding.UTF8.GetBytes(''), 16);
  server_write_iv := DeriveSecret('iv', server_secret,  TEncoding.UTF8.GetBytes(''), 12);
  client_secret := DeriveSecret('c ap traffic', master_secret_bytes, msgs_so_far_hash, 32);
  client_write_key := DeriveSecret('key', client_secret,  TEncoding.UTF8.GetBytes(''), 16);
  client_write_iv := DeriveSecret('iv', client_secret,  TEncoding.UTF8.GetBytes(''), 12);

  WriteLn('server_write_key: ', BytesToHexStr(server_write_key), ' server_write_iv: ', BytesToHexStr(server_write_iv));
  WriteLn('client_write_key: ', BytesToHexStr(client_write_key), ' client_write_iv: ', BytesToHexStr(client_write_iv));
  //  Reset sequence numbers
  client_seq_num := 0;
  server_seq_num := 0;
end;

function Send(Const REQUESTS: String): Integer;
begin
  WriteLn('--------------------');
  WriteLn('Request: ', REQUESTS);
  
  encrypted_msg := do_authenticated_encryption(client_write_key, client_write_iv, client_seq_num,
                                               TBytes([$17]),
                                               TEncoding.UTF8.GetBytes(REQUESTS));
  WriteLn(BytesToHexStr(TEncoding.UTF8.GetBytes(REQUESTS)));
  WriteLn(Length(encrypted_msg));
  SendTLS(CSocket, TLS_APPLICATION_DATA, encrypted_msg);
  client_seq_num += 1;
end;


function Recv(var decrypted_msg: TBytes): Integer;
begin
  WriteLn('Receiving an answer'); 
    repeat
        RecvTLSandDecrypt(CSocket, server_write_key, server_write_iv, server_seq_num, rec_type, decrypted_msg);
        server_seq_num += 1;
        case rec_type of
          Byte(TLS_APPLICATION_DATA): begin
                                        WriteLn(BytesToStr(decrypted_msg));
                                        Result := Length(decrypted_msg);
                                      end;
          Byte(TLS_HANDSHAKE):        if decrypted_msg[0] = 4
                                         then WriteLn('New session ticket: ', BytesToHexStr(decrypted_msg));
          Byte(TLS_ALERT):
            begin
              WriteLn('Got alert level: 0x', BytesToHexStr(decrypted_msg));
              Halt;
            end;
          else WriteLn ('Got msg with unknown rec_type', rec_type); 
          end;
      until rec_type = Byte(TLS_APPLICATION_DATA)
end;

function ConClose : Boolean;
begin
  CloseSocket(CSocket);
  Result := True;
end;
end.
