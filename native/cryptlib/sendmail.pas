unit sendmail;

{$mode objfpc}{$H+}

interface

uses
  SysUtils,
  base64,
  cryptlib
  ;

function SendMail(const SmtpServer, SenderEmail, Password, RecipientEmail, MailSubject, MailBody: string;
  SmtpPort: Integer): Boolean;

implementation

const
  TCP_PORT = 465; // TLS
  SMTP_RESPONSE_TIMEOUT = 5000; // 5 sec response timeout

//================================================================================
function Err2Str(instr: integer): string;
begin
  case instr of
    CRYPT_OK: Result := '';
    CRYPT_ERROR_PARAM1: Result := 'Bad argument, parameter 1';
    CRYPT_ERROR_PARAM2: Result := 'Bad argument, parameter 2';
    CRYPT_ERROR_PARAM3: Result := 'Bad argument, parameter 3';
    CRYPT_ERROR_PARAM4: Result := 'Bad argument, parameter 4';
    CRYPT_ERROR_PARAM5: Result := 'Bad argument, parameter 5';
    CRYPT_ERROR_PARAM6: Result := 'Bad argument, parameter 6';
    CRYPT_ERROR_PARAM7: Result := 'Bad argument, parameter 7';
    CRYPT_ERROR_MEMORY: Result := 'Out of memory';
    CRYPT_ERROR_NOTINITED: Result := 'Data has not been initialized';
    CRYPT_ERROR_INITED: Result := 'Data has already been initialized';
    CRYPT_ERROR_NOSECURE: Result := 'Opn.not available at requested sec.level';
    CRYPT_ERROR_RANDOM: Result := 'No reliable random data available';
    CRYPT_ERROR_FAILED: Result := 'Operation failed';
    CRYPT_ERROR_INTERNAL: Result := 'Internal consistency check failed';
    CRYPT_ERROR_NOTAVAIL: Result := 'This type of opn.not available';
    CRYPT_ERROR_PERMISSION: Result := 'No permission to perform this operation';
    CRYPT_ERROR_WRONGKEY: Result := 'Incorrect key used to decrypt data';
    CRYPT_ERROR_INCOMPLETE: Result := 'Operation incomplete/still in progress';
    CRYPT_ERROR_COMPLETE: Result := 'Operation complete/can''t continue';
    CRYPT_ERROR_TIMEOUT: Result := 'Operation timed out before completion';
    CRYPT_ERROR_INVALID: Result := 'Invalid/inconsistent information';
    CRYPT_ERROR_SIGNALLED: Result := 'Resource destroyed by external event';
    CRYPT_ERROR_OVERFLOW: Result := 'Resources/space exhausted';
    CRYPT_ERROR_UNDERFLOW: Result := 'Not enough data available';
    CRYPT_ERROR_BADDATA: Result := 'Bad/unrecognized data format';
    CRYPT_ERROR_SIGNATURE: Result := 'Signature/integrity check failed';
    CRYPT_ERROR_OPEN: Result := 'Cannot open object';
    CRYPT_ERROR_READ: Result := 'Cannot read item from object';
    CRYPT_ERROR_WRITE: Result := 'Cannot write item to object';
    CRYPT_ERROR_NOTFOUND: Result := 'Requested item not found in object';
    CRYPT_ERROR_DUPLICATE: Result := 'Item already present in object';
    CRYPT_ENVELOPE_RESOURCE: Result := 'Need resource to proceed';
  else
    Result := 'Unknown return code!';
  end;
end;

//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
function ErrExStr(hCrypt: CRYPT_SESSION): string;
var
  cBuff: array[0..511] of AnsiChar;
  MsgLen: integer;
begin
  MsgLen := SizeOf(cBuff);
  cryptGetAttributeString(hCrypt, CRYPT_ATTRIBUTE_ERRORMESSAGE, @cBuff, MsgLen);
  SetString(Result, cBuff, MsgLen);
end;


//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
function ParseStr(const sIn, sDelim: string; nField: Integer): string;
var
  match: Boolean;
  LenStr, LenDelim, ePos, sPos, count, k: Integer;
  sRet: string;
begin
  sRet := '';
  LenStr := Length(sIn);
  LenDelim := Length(sDelim);
  sPos := 1;
  count := 0;

  if (LenStr < 1) or (LenDelim < 1) then
    Exit(''); // Empty String

  if nField < 1 then
    Exit('');

  ePos := 1;
  while ePos <= LenStr do
  begin
    match := True;
    for k := 1 to LenDelim do
    begin
      if ePos + k - 1 > LenStr then
        Break
      else if sIn[ePos + k - 1] <> sDelim[k] then
      begin
        match := False;
        Break;
      end;
    end;

    if match or (ePos = LenStr) then
    begin
      if not match then
        ePos := LenStr + LenDelim;

      Inc(count);
      if count = nField then
      begin
        sRet := Copy(sIn, sPos, ePos - sPos);
        Break;
      end;

      Inc(ePos, LenDelim);
      sPos := ePos;
    end
    else
      Inc(ePos);
  end;

  Result := sRet;
end;

//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
function SMTPLnCode(const sLine: string): integer;
var
  Code: integer;
begin
  Code := 0;

  if Length(sLine) >= 3 then
    Val(Copy(sLine, 1, 3), Code);

  Result := Code;
  WriteLn('Server responce code: ' + IntToStr(Code));
end;

//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
function TLSPop(hCrypt: integer; var sErr, sReply: string; nRetLn: integer): integer;
// Handles responses that are delayed, lines that are delayed, missing end of response
// Each line of the SMTP response must be terminated by <CRLF>
// In Multi-Line returns, each SMTP code will be followed by a hyphen, except the last line
var
  k, RetVal, BytesReply, Last, Totms, count, BufLen: integer;
  cBuff: PChar;
  sBuff: string;
begin
  BufLen := 255;
  GetMem(cBuff, BufLen);

  // Recover unexpected data
  if nRetLn < 1 then
  begin
    RetVal := cryptPopData(hCrypt, cBuff, BufLen, BytesReply);
    if RetVal <> CRYPT_OK then
    begin
      sErr := 'cryptPopData ERROR: ' + Err2Str(RetVal) + ' - ' + ErrExStr(hCrypt);
      Result := -22;
    end
    else if BytesReply > 0 then
    begin
      sErr := cBuff;
      Result := BytesReply;
    end
    else
      Result := 0;
    Exit;
  end
  else
  begin
    sReply := '';
    count := 0;
    while count < nRetLn do
    begin
      Totms := 0;
      while True do
      begin
        Sleep(80);
        Inc(Totms, 80);
        if Totms > SMTP_RESPONSE_TIMEOUT then
        begin
          sErr := 'Response timeout exceeded';
          Result := -28;
          Exit;
        end;

        RetVal := cryptPopData(hCrypt, cBuff, BufLen, BytesReply);
        if RetVal <> CRYPT_OK then
        begin
          sErr := 'cryptPopData ERROR: ' + Err2Str(RetVal) + ' - ' + ErrExStr(hCrypt);
          Result := -29;
          Exit;
        end
        else if BytesReply > 0 then
        begin
          sBuff := cBuff;
          sReply += Copy(sBuff, 1, BytesReply);
          WriteLn(sReply);
          Last := Length(sReply);
          //WriteLn('Last: ' + IntToStr(Last));
          if (Last > 5) and (Ord(sReply[Last]) = 10) and (Ord(sReply[Last - 1]) = 13) then
          begin
            for k := 4 to Last - 1 do
            begin
              //WriteLn('K: ' + IntToStr(k) + ' ' + IntToStr(Last - k) + ' ' + IntToStr(Last - k + 4));
              if (sReply[Last - k] = #10) and (sReply[Last - k + 4] = ' ') then
              begin
                //WriteLn('Found 1');
                Inc(count);
                Break;
              end;
              if (k = Last - 1) and (sReply[Last - k + 3] = ' ') then
              begin
                //WriteLn('Found 2');
                Inc(count);
                Break;
              end;
            end;
          end;
        end;
        Break;
      end;
    end;
  end;

  Result := SMTPLnCode(ParseStr(sReply, #13#10, count));
end;

//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
function TLSPushPop(hCrypt: integer; var sErr, sReply: string; nRetLn: integer; sSend: string): integer;
// Handles responses that are delayed, lines that are delayed, missing end of response
// Each line of the SMTP response must be terminated by <CRLF>
// In Multi-Line returns, each SMTP code will be followed by a hyphen, except the last line
var
  RetVal, BytesSent: integer;
begin
  // Trap unexpected returns
  RetVal := TLSPop(hCrypt, sErr, sReply, 0);
  //WriteLn('Trap unexpected returns: ' + sErr);
  if RetVal < 0 then
  begin
    Result := RetVal;
    Exit;
  end;

  WriteLn('Data to send: ' + sSend);
  // Push data 
  if (Length(sSend) = 0) or (nRetLn <= 0) then
  begin
    sErr := 'No data to send';
    Result := -24;
    Exit;
  end;

  // Push data
  RetVal := cryptPushData(hCrypt, @sSend[1], Length(sSend), BytesSent);
  if RetVal <> CRYPT_OK then
  begin
    sErr := 'CryptPushData ERROR: ' + Err2Str(RetVal) + ' - ' + ErrExStr(hCrypt);
    Result := -25;
    Exit;
  end
  else if Length(sSend) <> BytesSent then
  begin
    sErr := 'CryptPushData ERROR: ToSend=' + IntToStr(Length(sSend)) + ', Sent=' + IntToStr(BytesSent);
    Result := -26;
    Exit;
  end;
  
  // Flush outgoing data
  RetVal := cryptFlushData(hCrypt);
  if RetVal <> CRYPT_OK then
  begin
    sErr := 'CryptFlushData ERROR: ' + Err2Str(RetVal) + ' - ' + ErrExStr(hCrypt);
    Result := -27;
    Exit;
  end;

  // Recover response
  RetVal := TLSPop(hCrypt, sErr, sReply, nRetLn); 
  if RetVal < 0 then
  begin
    Result := RetVal;
    Exit;
  end;

  Result := RetVal;
end;

//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
function SMTPTLS(const sSrvr, sUser, sPass, sFrom, sTo, sBody: string; var sErr: string): integer;
var
  RetVal, FuncRet, hSess: integer;
  sSend, sReply: string;
begin
  if cryptInit() <> CRYPT_OK then
    Exit(-2);

  FuncRet := 1;

  while True do
  begin
    // Create the session
    RetVal := cryptCreateSession(hSess, CRYPT_UNUSED, CRYPT_SESSION_SSL);
    if RetVal <> CRYPT_OK then
    begin
      sErr := 'CryptCreateSession ERROR: ' + Err2Str(RetVal);
      FuncRet := -4;
      Break;
    end;

    // Set socket read timeout
    RetVal := cryptSetAttribute(hSess, CRYPT_OPTION_NET_READTIMEOUT, 0 );

    // Add the server name
    RetVal := cryptSetAttributeString(hSess, CRYPT_SESSINFO_SERVER_NAME, @sSrvr[1], Length(sSrvr));
    if RetVal <> CRYPT_OK then
    begin
      sErr := 'SERVER_NAME ERROR: ' + Err2Str(RetVal) + ' ' + ErrExStr(hSess);
      FuncRet := -6;
      Break;
    end
    else writeln('SERVER_NAME: ' + sSrvr);

    // Specify the Port
    RetVal := cryptSetAttribute(hSess, CRYPT_SESSINFO_SERVER_PORT, TCP_PORT);
    if RetVal <> CRYPT_OK then
    begin
      sErr := 'SERVER_PORT ERROR: ' + Err2Str(RetVal) + ' ' + ErrExStr(hSess);
      FuncRet := -8;
      Break;
    end
    else writeln('SERVER_PORT: ' + IntToStr(TCP_PORT));

    // Activate the session
    RetVal := cryptSetAttribute(hSess, CRYPT_SESSINFO_ACTIVE, 1);
    if RetVal <> CRYPT_OK then
    begin
      sErr := 'SESSINFO_ACTIVE ERROR: ' + Err2Str(RetVal) + ' ' + ErrExStr(hSess);
      FuncRet := -10;
      Break;
    end
    else writeln('Session established.');

    Sleep(100); // Wait for some time for hello message from server

    // Discard initial response created by connecting
    RetVal := TLSPop(hSess, sErr, sReply, 0);
    if RetVal < 0 then
    begin
      FuncRet := -12;
      Break;
    end;

    // MIME dialog
    sSend := 'EHLO fpmail' + #13#10; // ESMTP version of HELO
    RetVal := TLSPushPop(hSess, sErr, sReply, 1, sSend);
    if RetVal < 0 then
      Exit(RetVal);
    if RetVal <> 250 then
    begin
      sErr := 'EHLO Failed: ' + sErr;
      FuncRet := -14;
      Break;
    end
    else writeln('EHLO ok');

    RetVal := TLSPushPop(hSess, sErr, sReply, 1, 'AUTH LOGIN ' + #13#10); // Login
    if RetVal <> 334 then
    begin
      sErr := 'AUTH Failed: ' + sErr;
      FuncRet := -16;
      Break;
    end;

    RetVal := TLSPushPop(hSess, sErr, sReply, 1, EncodeStringBase64(sUser) + #13#10); // MimeEncode Username
    if RetVal <> 334 then
    begin
      sErr := 'user Failed: ' + sErr;
      FuncRet := -18;
      Break;
    end;

    RetVal := TLSPushPop(hSess, sErr, sReply, 1, EncodeStringBase64(sPass) + #13#10); // MimeEncode Password
    if RetVal <> 235 then
    begin
      sErr := 'pass Failed: ' + sErr;
      FuncRet := -20;
      Break;
    end;

    RetVal := TLSPushPop(hSess, sErr, sReply, 1, 'MAIL FROM: <' + sFrom + '>' + #13#10); // Sender
    if RetVal <> 250 then
    begin
      sErr := 'MAIL FROM Failed: ' + sErr;
      FuncRet := -22;
      Break;
    end;

    RetVal := TLSPushPop(hSess, sErr, sReply, 1, 'RCPT TO: <' + sTo + '>' + #13#10); // Recipient
    if RetVal <> 250 then
    begin
      sErr := 'RCPT TO Failed: ' + sErr;
      FuncRet := -24;
      Break;
    end;

    RetVal := TLSPushPop(hSess, sErr, sReply, 1, 'DATA ' + #13#10); // Body begins
    if RetVal <> 354 then
    begin
      sErr := 'DATA Failed: ' + sErr;
      FuncRet := -26;
      Break;
    end;

    RetVal := TLSPushPop(hSess, sErr, sReply, 1, sBody + #13#10 + '.' + #13#10); // Body
    if RetVal <> 250 then
    begin
      sErr := 'body Failed: ' + sErr;
      FuncRet := -28;
      Break;
    end;

    sErr := 'Email Sent OK';
    Result := 1;
    Exit; // 250 2.0.0 OK - Message sent

    RetVal := TLSPushPop(hSess, sErr, sReply, 1, 'QUIT ' + #13#10); // Terminate MIME
    if RetVal < 0 then
      Exit(RetVal);
    if RetVal <> 221 then
    begin
      sErr := 'QUIT Failed: ' + sErr;
      FuncRet := -39;
      Break;
    end;

    Break;
  end;

  if hSess <> 0 then
    cryptDestroySession(hSess); // Close the session

  cryptEnd();
  Result := FuncRet;
end;

//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
function SendMail(const SmtpServer, SenderEmail, Password, RecipientEmail, MailSubject, MailBody: string;
  SmtpPort: Integer): Boolean;
var
  RetVal: integer;
  sErr: string;
begin
  RetVal := SMTPTLS(SmtpServer,
    SenderEmail,
    Password,
    SenderEmail,
    RecipientEmail,
    MailBody,
    sErr);

  if RetVal < 0 then
    Result:=False
  else
    Result:=True;
end;

end.
