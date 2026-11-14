%%{
  # RFC 8601 Message Authentication-Results
  # https://tools.ietf.org/html/rfc8601
  machine rfc8601_authentication_results;
  alphtype int;

  include rfc5234_abnf_core_rules "rfc5234_abnf_core_rules.rl";

  # RFC 5322 3.2.1 Quoted characters
  obs_NO_WS_CTL = 0x01..0x08 | "\v" | "\f" | 0x0e..0x1f | 0x7f;
  obs_qp = "\\" (0x00 | obs_NO_WS_CTL | LF | CR);
  quoted_pair = ("\\" (VCHAR | WSP)) | obs_qp;

  # RFC 5322 3.2.2 Folding White Space and Comments.
  # Comments are captured (without their outer parentheses) via the
  # comment_begin/comment_exit actions so that comment text is never
  # mistaken for a methodspec/result token.
  obs_FWS = (CRLF? WSP)+;
  FWS = (WSP* CRLF WSP+) | (CRLF WSP+) | obs_FWS;
  rfc5322_ctext = 0x21..0x27 | 0x2a..0x5b | 0x5d..0x7e | obs_NO_WS_CTL;
  ctext = rfc5322_ctext | utf8_non_ascii; # RFC6532 for UTF-8
  ccontent = ctext | quoted_pair | "(" @comment_begin;
  comment_tail := (FWS? ccontent)* FWS? ")" @comment_exit;
  comment = "(" @comment_begin;
  CFWS = ((FWS? comment)+ FWS?) | FWS;

  # RFC 5322 3.2.4 Quoted Strings
  rfc5322_qtext = 0x21 | 0x23..0x5b | 0x5d..0x7e | obs_NO_WS_CTL;
  qtext = rfc5322_qtext | utf8_non_ascii; # RFC6532 for UTF-8
  qcontent = qtext | quoted_pair;
  quoted_string = CFWS?
                  (DQUOTE
                    (((FWS? qcontent)* FWS?) >qstr_s %qstr_e)
                  DQUOTE)
                  CFWS?;

  # RFC 8601 4.  Authentication-Results Header Field
  #
  # Keyword = ALPHA *(ALPHA / DIGIT / "_" / "-" / ".")
  keyword = ALPHA (ALPHA | DIGIT | "_" | "-" | ".")*;

  # RFC 2045 5.1 token: any CHAR except SPACE, CTLs or tspecials
  token_char = ALPHA | DIGIT | "!" | "#" | "$" | "%" | "&" | "'" |
               "*" | "+" | "-" | "." | "^" | "_" | "`" | "{" | "|" |
               "}" | "~";

  # pvalue = [CFWS] (value / [[local-part] "@"] domain-name) [CFWS]
  # Accept any printable char that cannot be confused with the
  # surrounding grammar (WSP, ";", comment and quoting delimiters).
  pvalue_char = (0x21..0x7e -- (";" | "(" | ")" | DQUOTE | "\\")) |
                utf8_non_ascii;

  # authserv-id = value  (value = token / quoted-string)
  authserv_id = (token_char+ >authserv_id_s %authserv_id_e) |
                (quoted_string %authserv_id_quoted);

  # authres-version = 1*DIGIT [CFWS]
  authres_version = DIGIT+ >version_s %version_e;

  # reasonspec = "reason" [CFWS] "=" [CFWS] value
  reasonspec = "reason"i CFWS? "=" CFWS?
               ((token_char+ >reason_s %reason_e) |
                (quoted_string %reason_quoted));

  # propspec = ptype [CFWS] "." [CFWS] property [CFWS] "=" pvalue
  propspec = (keyword >prop_type_s %prop_type_e) CFWS? "." CFWS?
             (keyword >prop_name_s %prop_name_e) CFWS? "=" CFWS?
             ((pvalue_char+ >prop_value_s %prop_value_e) |
              (quoted_string %prop_value_quoted));

  # methodspec = [CFWS] method [CFWS] "=" [CFWS] result
  # method = Keyword [[CFWS] "/" [CFWS] method-version]
  method_version = DIGIT+ >method_version_s %method_version_e;
  methodspec = (keyword >method_s %method_e)
               (CFWS? "/" CFWS? method_version)?;
  method_result = methodspec CFWS? "=" CFWS?
                  (keyword >result_s %result_e)
                  (CFWS (reasonspec | propspec))*;

  # authres-payload = "none" / authres-results
  none_payload = "none"i %none_e;
  payload_entry = none_payload | method_result;

  # authres-header-field body:
  #   [CFWS] authserv-id [[CFWS] "/" [CFWS] authres-version]
  #     *([CFWS] ";" [CFWS] authres-payload) [CFWS]
  # Empty ";" entries (no-result) are tolerated.
  authentication_results = CFWS? authserv_id
                           (CFWS? "/" CFWS? authres_version)?
                           (CFWS? ";" (CFWS? payload_entry)?)* CFWS?;
}%%
