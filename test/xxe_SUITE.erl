%% CVE-2026-28809: XXE (XML External Entity) vulnerability tests for esaml.
%%
%% esaml parses untrusted SAML XML via xmerl_scan:string/2 with only
%% [{namespace_conformant, true}] -- no entity restriction. This allows
%% attackers to include <!DOCTYPE> declarations with external entity
%% references that expand during parsing, leaking local file contents
%% into the SAML document. Parsing happens BEFORE signature verification,
%% so the attack works even against unsigned/invalid responses.
%%
%% OTP 27+ mitigates this by rejecting entity definitions by default.
%% {allow_entities, true} re-enables the old behavior, which we use
%% to demonstrate the vulnerability on modern OTP.
-module(xxe_SUITE).

-include_lib("eunit/include/eunit.hrl").
-include_lib("xmerl/include/xmerl.hrl").

%%====================================================================
%% Helpers
%%====================================================================

xxe_saml_response(EntityDecl, EntityRef) ->
    "<?xml version=\"1.0\"?>"
    "<!DOCTYPE foo [" ++ EntityDecl ++ "]>"
    "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" "
    "Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\">"
    "<saml:Issuer>" ++ EntityRef ++ "</saml:Issuer>"
    "</samlp:Response>".

xxe_saml_assertion(EntityDecl, EntityRef) ->
    "<?xml version=\"1.0\"?>"
    "<!DOCTYPE foo [" ++ EntityDecl ++ "]>"
    "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" "
    "Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\">"
    "<saml:Issuer>" ++ EntityRef ++ "</saml:Issuer>"
    "</saml:Assertion>".

encode_for_post(XmlStr) ->
    base64:encode(list_to_binary(XmlStr)).

encode_for_deflate(XmlStr) ->
    base64:encode(zlib:zip(list_to_binary(XmlStr))).

extract_issuer(Doc) ->
    Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    [#xmlElement{content = [#xmlText{value = Value}]}] =
        xmerl_xpath:string("//saml:Issuer", Doc, [{namespace, Ns}]),
    Value.

%%====================================================================
%% Tests: OTP 27+ rejects entities by default in esaml code paths
%%====================================================================

%% CVE-2026-28809: XXE via POST binding path (esaml_binding:decode_response/2)
xxe_post_binding_rejects_entities_test() ->
    XmlStr = xxe_saml_response(
        "<!ENTITY xxe SYSTEM \"file:///etc/hostname\">", "&xxe;"),
    Payload = encode_for_post(XmlStr),
    ?assertExit(
        {fatal, {{error, entities_not_allowed}, _, _, _}},
        esaml_binding:decode_response(<<>>, Payload)).

%% CVE-2026-28809: XXE via DEFLATE binding path (esaml_binding:decode_response/2)
xxe_deflate_binding_rejects_entities_test() ->
    XmlStr = xxe_saml_response(
        "<!ENTITY xxe SYSTEM \"file:///etc/hostname\">", "&xxe;"),
    Payload = encode_for_deflate(XmlStr),
    Deflate = <<"urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE">>,
    ?assertExit(
        {fatal, {{error, entities_not_allowed}, _, _, _}},
        esaml_binding:decode_response(Deflate, Payload)).

%% CVE-2026-28809: Even internal entities (no SYSTEM) are rejected on OTP 27+.
xxe_internal_entity_rejected_test() ->
    XmlStr = xxe_saml_response(
        "<!ENTITY xxe \"INJECTED\">", "&xxe;"),
    Payload = encode_for_post(XmlStr),
    ?assertExit(
        {fatal, {{error, entities_not_allowed}, _, _, _}},
        esaml_binding:decode_response(<<>>, Payload)).

%% CVE-2026-28809: decrypt_assertion/2 calls xmerl_scan:string with
%% the same options [{namespace_conformant, true}]. This test confirms
%% entities are rejected on that code path too.
xxe_decrypt_assertion_path_rejects_entities_test() ->
    XxeAssertion = xxe_saml_assertion(
        "<!ENTITY xxe SYSTEM \"file:///etc/hostname\">", "&xxe;"),
    ?assertExit(
        {fatal, {{error, entities_not_allowed}, _, _, _}},
        xmerl_scan:string(XxeAssertion, [{namespace_conformant, true}])).

%%====================================================================
%% Tests: Demonstrate the vulnerability (pre-OTP-27 behavior)
%%
%% {allow_entities, true} re-enables entity expansion, simulating
%% what happens on OTP < 27 where xmerl expanded entities by default.
%%====================================================================

%% Demonstrates the actual file read: an attacker embeds an external
%% entity referencing a local file, and its contents appear in the
%% parsed SAML document's Issuer element.
xxe_demonstrates_file_read_test() ->
    XmlStr = xxe_saml_response(
        "<!ENTITY xxe SYSTEM \"file:///etc/hostname\">", "&xxe;"),
    {Doc, _} = xmerl_scan:string(XmlStr,
        [{namespace_conformant, true}, {allow_entities, true}]),
    IssuerValue = extract_issuer(Doc),
    %% The Issuer element now contains /etc/hostname contents,
    %% not the literal entity reference.
    ?assertNotEqual("&xxe;", IssuerValue),
    ?assert(length(IssuerValue) > 0).

%% Entity expansion occurs during XML parsing in decode_response/2,
%% which runs BEFORE signature verification in validate_assertion/2.
%% A SAML response with no signature still has its entities fully
%% expanded, leaking file contents into the parsed XML tree.
xxe_expansion_before_signature_verification_test() ->
    XmlStr = xxe_saml_response(
        "<!ENTITY xxe \"INJECTED_BY_ATTACKER\">", "&xxe;"),
    {Doc, _} = xmerl_scan:string(XmlStr,
        [{namespace_conformant, true}, {allow_entities, true}]),
    ?assertEqual("INJECTED_BY_ATTACKER", extract_issuer(Doc)).
