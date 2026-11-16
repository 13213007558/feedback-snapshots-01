# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require 'nokogiri'
require "digest/sha1"
require "digest/sha2"
require "onelogin/ruby-saml/utils"
require "onelogin/ruby-saml/error_handling"

module XMLSecurity

  class BaseDocument < REXML::Document
    REXML::Document::entity_expansion_limit = 0

    C14N            = "http://www.w3.org/2001/10/xml-exc-c14n#"
    C14N_WITH_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
    C14N_1_0        = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    C14N_1_0_WITH_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
    C14N_1_1        = "http://www.w3.org/2006/12/xml-c14n11"
    C14N_1_1_WITH_COMMENTS = "http://www.w3.org/2006/12/xml-c14n11#WithComments"
    DSIG            = "http://www.w3.org/2000/09/xmldsig#"
    ENVELOPED_SIG   = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    NOKOGIRI_OPTIONS = Nokogiri::XML::ParseOptions::STRICT |
                       Nokogiri::XML::ParseOptions::NONET

    # Canonicalization algorithms that may be selected independently by
    # SignedInfo/CanonicalizationMethod and by each Reference transform.
    # The value records the libxml2 mode and whether comments are part of
    # the canonical form. +InclusiveNamespaces+ is only defined for
    # exclusive c14n and is therefore resolved from the same element that
    # declared the algorithm.
    C14N_ALGORITHMS = {
      C14N_1_0 => { :mode => Nokogiri::XML::XML_C14N_1_0, :with_comments => false },
      C14N_1_0_WITH_COMMENTS => { :mode => Nokogiri::XML::XML_C14N_1_0, :with_comments => true },
      C14N_1_1 => { :mode => Nokogiri::XML::XML_C14N_1_1, :with_comments => false },
      C14N_1_1_WITH_COMMENTS => { :mode => Nokogiri::XML::XML_C14N_1_1, :with_comments => true },
      C14N => { :mode => Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0, :with_comments => false },
      C14N_WITH_COMMENTS => { :mode => Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0, :with_comments => true }
    }.freeze

    # Safety load the SAML Message XML
    # @param document [REXML::Document] The message to be loaded
    # @param check_malformed_doc [Boolean] check_malformed_doc Enable or Disable the check for malformed XML
    # @return [Nokogiri::XML] The nokogiri document
    # @raise [ValidationError] If there was a problem loading the SAML Message XML
    def self.safe_load_xml(document, check_malformed_doc = true)
      doc_str = document.to_s
      if doc_str.include?("<!DOCTYPE")
       raise StandardError.new("Dangerous XML detected. No Doctype nodes allowed")
      end

      begin
        xml = Nokogiri::XML(doc_str) do |config|
          config.options = self::NOKOGIRI_OPTIONS
        end
      rescue StandardError => error
        raise StandardError.new(error.message)
      end

      if xml.internal_subset
        raise StandardError.new("Dangerous XML detected. No Doctype nodes allowed")
      end

      unless xml.errors.empty?
        raise StandardError.new("There were XML errors when parsing: #{xml.errors}") if check_malformed_doc
      end

      xml
    end

    def canon_algorithm(element)
      canonicalization_spec(element)[:mode]
    end

    # Resolve the canonicalization algorithm declared by an element.
    # Returns a descriptor with the libxml2 mode and the comment policy so
    # callers never have to infer either from a different signature layer.
    # Unknown algorithms retain the historical exclusive-c14n fallback.
    def canonicalization_spec(element)
      algorithm = element
      if algorithm.is_a?(REXML::Element)
        attribute = element.attribute('Algorithm')
        algorithm = attribute && attribute.value
      end

      C14N_ALGORITHMS[algorithm] || C14N_ALGORITHMS[C14N]
    end

    def algorithm(element)
      algorithm = element
      if algorithm.is_a?(REXML::Element)
        algorithm = element.attribute("Algorithm").value
      end

      algorithm = algorithm && algorithm =~ /(rsa-)?sha(.*?)$/i && $2.to_i

      case algorithm
      when 256 then OpenSSL::Digest::SHA256
      when 384 then OpenSSL::Digest::SHA384
      when 512 then OpenSSL::Digest::SHA512
      else
        OpenSSL::Digest::SHA1
      end
    end

  end

  class Document < BaseDocument
    RSA_SHA1        = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    RSA_SHA256      = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    RSA_SHA384      = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    RSA_SHA512      = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    SHA1            = "http://www.w3.org/2000/09/xmldsig#sha1"
    SHA256          = 'http://www.w3.org/2001/04/xmlenc#sha256'
    SHA384          = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    SHA512          = 'http://www.w3.org/2001/04/xmlenc#sha512'
    INC_PREFIX_LIST = "#default samlp saml ds xs xsi md"

    attr_writer :uuid

    def uuid
      @uuid ||= begin
        document.root.nil? ? nil : document.root.attributes['ID']
      end
    end

    #<Signature>
      #<SignedInfo>
        #<CanonicalizationMethod />
        #<SignatureMethod />
        #<Reference>
           #<Transforms>
           #<DigestMethod>
           #<DigestValue>
        #</Reference>
        #<Reference /> etc.
      #</SignedInfo>
      #<SignatureValue />
      #<KeyInfo />
      #<Object />
    #</Signature>
    def sign_document(private_key, certificate, signature_method = RSA_SHA1, digest_method = SHA1, check_malformed_doc = true)
      noko = XMLSecurity::BaseDocument.safe_load_xml(self.to_s, check_malformed_doc)

      signature_element = REXML::Element.new("ds:Signature").add_namespace('ds', DSIG)
      signed_info_element = signature_element.add_element("ds:SignedInfo")
      signed_info_element.add_element("ds:CanonicalizationMethod", {"Algorithm" => C14N})
      signed_info_element.add_element("ds:SignatureMethod", {"Algorithm"=>signature_method})

      # Add Reference
      reference_element = signed_info_element.add_element("ds:Reference", {"URI" => "##{uuid}"})

      # Add Transforms
      transforms_element = reference_element.add_element("ds:Transforms")
      transforms_element.add_element("ds:Transform", {"Algorithm" => ENVELOPED_SIG})
      c14element = transforms_element.add_element("ds:Transform", {"Algorithm" => C14N})
      c14element.add_element("ec:InclusiveNamespaces", {"xmlns:ec" => C14N, "PrefixList" => INC_PREFIX_LIST})

      digest_method_element = reference_element.add_element("ds:DigestMethod", {"Algorithm" => digest_method})
      inclusive_namespaces = INC_PREFIX_LIST.split(" ")
      canon_doc = noko.canonicalize(canon_algorithm(C14N), inclusive_namespaces)
      reference_element.add_element("ds:DigestValue").text = compute_digest(canon_doc, algorithm(digest_method_element))

      # add SignatureValue
      noko_sig_element = XMLSecurity::BaseDocument.safe_load_xml(signature_element.to_s, check_malformed_doc)

      noko_signed_info_element = noko_sig_element.at_xpath('//ds:Signature/ds:SignedInfo', 'ds' => DSIG)
      canon_string = noko_signed_info_element.canonicalize(canon_algorithm(C14N), nil, false)

      signature = compute_signature(private_key, algorithm(signature_method).new, canon_string)
      signature_element.add_element("ds:SignatureValue").text = signature

      # add KeyInfo
      key_info_element       = signature_element.add_element("ds:KeyInfo")
      x509_element           = key_info_element.add_element("ds:X509Data")
      x509_cert_element      = x509_element.add_element("ds:X509Certificate")
      if certificate.is_a?(String)
        certificate = OpenSSL::X509::Certificate.new(certificate)
      end
      x509_cert_element.text = Base64.encode64(certificate.to_der).gsub(/\n/, "")

      # add the signature
      if issuer_element = elements["//saml:Issuer"]
        root.insert_after(issuer_element, signature_element)
      elsif issuer_element = elements["//saml2:Issuer"]
        root.insert_after(issuer_element, signature_element)
      elsif first_child = root.children[0]
        root.insert_before(first_child, signature_element)
      else
        root.add_element(signature_element)
      end
    end

    protected

    def compute_signature(private_key, signature_algorithm, document)
      Base64.encode64(private_key.sign(signature_algorithm, document)).gsub(/\n/, "")
    end

    def compute_digest(document, digest_algorithm)
      digest = digest_algorithm.digest(document)
      Base64.encode64(digest).strip
    end

  end

  class SignedDocument < BaseDocument
    include OneLogin::RubySaml::ErrorHandling

    attr_writer :signed_element_id
    attr_reader :reference_canonicalization, :signed_info_canonicalization

    def initialize(response, errors = [])
      @raw_document = response.to_s
      super(response)
      @errors = errors
      reset_elements
    end

    def reset_elements
      @referenced_xml = nil
      @cached_signed_info = nil
      @signature = nil
      @signature_algorithm = nil
      @ref = nil
      @processed = false
      @working_copy = nil
      @signed_info_canonicalization = nil
      @reference_canonicalization = nil
    end

    def processed
      @processed
    end

    def referenced_xml
      @referenced_xml
    end

    def signed_element_id
      @signed_element_id ||= extract_signed_element_id
    end

    # Validates the referenced_xml, which is the signed part of the document
    def validate_document(idp_cert_fingerprint, soft = true, options = {})
      # get cert from response
      cert_element = REXML::XPath.first(
        self,
        "//ds:X509Certificate",
        { "ds"=>DSIG }
      )

      if cert_element
        base64_cert = OneLogin::RubySaml::Utils.element_text(cert_element)
        cert_text = Base64.decode64(base64_cert)
        begin
          cert = OpenSSL::X509::Certificate.new(cert_text)
        rescue OpenSSL::X509::CertificateError => _e
          return append_error("Document Certificate Error", soft)
        end

        if options[:fingerprint_alg]
          fingerprint_alg = XMLSecurity::BaseDocument.new.algorithm(options[:fingerprint_alg]).new
        else
          fingerprint_alg = OpenSSL::Digest.new('SHA1')
        end
        fingerprint = fingerprint_alg.hexdigest(cert.to_der)

        # check cert matches registered idp cert
        if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/,"").downcase
          return append_error("Fingerprint mismatch", soft)
        end
        base64_cert = Base64.encode64(cert.to_der)
      else
        if options[:cert]
          base64_cert = Base64.encode64(options[:cert].to_pem)
        else
          if soft
            return false
          else
            return append_error("Certificate element missing in response (ds:X509Certificate) and not cert provided at settings", soft)
          end
        end
      end
      validate_signature(base64_cert, soft)
    end

    def validate_document_with_cert(idp_cert, soft = true)
      # get cert from response
      cert_element = REXML::XPath.first(
        self,
        "//ds:X509Certificate",
        { "ds"=>DSIG }
      )

      if cert_element
        base64_cert = OneLogin::RubySaml::Utils.element_text(cert_element)
        cert_text = Base64.decode64(base64_cert)
        begin
          cert = OpenSSL::X509::Certificate.new(cert_text)
        rescue OpenSSL::X509::CertificateError => _e
          return append_error("Document Certificate Error", soft)
        end

        # check saml response cert matches provided idp cert
        if idp_cert.to_pem != cert.to_pem
          return append_error("Certificate of the Signature element does not match provided certificate", soft)
        end
      end

      encoded_idp_cert = Base64.encode64(idp_cert.to_pem)
      validate_signature(encoded_idp_cert, true)
    end

    def cache_referenced_xml(soft, check_malformed_doc = true)
      reset_elements
      @processed = true

      begin
        nokogiri_document = XMLSecurity::BaseDocument.safe_load_xml(@raw_document, check_malformed_doc)
      rescue StandardError => error
        @errors << error.message
        return false if soft
        raise ValidationError.new("XML load failed: #{error.message}")
      end

      # create a rexml document
      @working_copy ||= REXML::Document.new(self.to_s).root

      # get signature node
      sig_element = REXML::XPath.first(
          @working_copy,
          "//ds:Signature",
          {"ds"=>DSIG}
      )

      return if sig_element.nil?

      # signature method
      sig_alg_value = REXML::XPath.first(
        sig_element,
        "./ds:SignedInfo/ds:SignatureMethod",
        {"ds"=>DSIG}
      )
      @signature_algorithm = algorithm(sig_alg_value)

      # get signature
      base64_signature = REXML::XPath.first(
        sig_element,
        "./ds:SignatureValue",
        {"ds" => DSIG}
      )

      return if base64_signature.nil?

      base64_signature_text = OneLogin::RubySaml::Utils.element_text(base64_signature)
      @signature = base64_signature_text.nil? ? nil : Base64.decode64(base64_signature_text)

      noko_sig_element = nokogiri_document.at_xpath('//ds:Signature', 'ds' => DSIG)
      noko_signed_info_element = noko_sig_element.at_xpath('./ds:SignedInfo', 'ds' => DSIG)

      # SignedInfo has its own canonicalization method and, when exclusive
      # c14n is used, its own InclusiveNamespaces child. These are never
      # inherited from a Reference transform.
      @signed_info_canonicalization = canonicalization_for(
        sig_element,
        './ds:SignedInfo/ds:CanonicalizationMethod'
      )
      @cached_signed_info = noko_signed_info_element.canonicalize(
        @signed_info_canonicalization[:mode],
        @signed_info_canonicalization[:inclusive_namespaces],
        @signed_info_canonicalization[:with_comments]
      )

      # The Reference and its transforms are read from the original REXML
      # tree, not from the canonicalized SignedInfo, because canonicalization
      # may add or move namespace declarations used by the transform nodes.
      @ref = REXML::XPath.first(sig_element, "./ds:SignedInfo/ds:Reference", {"ds"=>DSIG})
      return if @ref.nil?

      # Resolve the target before removing the signature: the digest covers
      # the document as received with the enveloped signature node absent.
      enclosing_id = sig_element.parent && sig_element.parent.attributes["ID"]
      referenced_id = reference_id(@ref) || enclosing_id
      reference_nodes = nokogiri_document.xpath("//*[@ID=$id]", nil, { 'id' => referenced_id })

      hashed_element = reference_nodes[0]
      return if hashed_element.nil?

      # Remove the signature that is enveloped by the referenced element,
      # matching the enveloped-signature transform. This must happen after
      # SignedInfo is canonicalized and before the Reference canonicalization.
      remove_enveloped_signature(nokogiri_document, sig_element, hashed_element)

      @reference_canonicalization = reference_canonicalization_for(@ref)

      @referenced_xml = hashed_element.canonicalize(
        @reference_canonicalization[:mode],
        @reference_canonicalization[:inclusive_namespaces],
        @reference_canonicalization[:with_comments]
      )
    end

    def validate_signature(base64_cert, soft = true)
      if !@processed
        cache_referenced_xml(soft)
      end

      return append_error("No Signature Algorithm Method found", soft) if @signature_algorithm.nil?  
      return append_error("No Signature node found", soft) if @signature.nil?  
      return append_error("No canonized SignedInfo ", soft) if @cached_signed_info.nil?
      return append_error("No Reference node found", soft) if @ref.nil?
      return append_error("No referenced XML", soft) if @referenced_xml.nil?

      # get certificate object
      cert_text = Base64.decode64(base64_cert)
      cert = OpenSSL::X509::Certificate.new(cert_text)

      digest_algorithm = algorithm(REXML::XPath.first(
        @ref,
        "./ds:DigestMethod",
        { "ds" => DSIG }
      ))
      hash = digest_algorithm.digest(@referenced_xml)
      encoded_digest_value = REXML::XPath.first(
        @ref,
        "./ds:DigestValue",
        { "ds" => DSIG }
      )
      encoded_digest_value_text = OneLogin::RubySaml::Utils.element_text(encoded_digest_value)
      digest_value = encoded_digest_value_text.nil? ? nil : Base64.decode64(encoded_digest_value_text)

      # Compare the computed "hash" with the "signed" hash
      unless hash && hash == digest_value
        return append_error("Digest mismatch", soft)
      end

      # verify signature
      unless cert.public_key.verify(@signature_algorithm.new, @signature, @cached_signed_info)
        return append_error("Key validation error", soft)
      end

      return true
    end

    private

    # Resolve the canonicalization declared by +xpath+ under +parent+.
    # InclusiveNamespaces is read from the algorithm element itself, so a
    # prefix list on SignedInfo never becomes a Reference parameter (or the
    # other way around).
    def canonicalization_for(parent, xpath)
      element = REXML::XPath.first(parent, xpath, { "ds" => DSIG })
      spec = canonicalization_spec(element).dup
      spec[:inclusive_namespaces] = inclusive_namespaces_for(element, spec)
      spec
    end

    # Resolve the transforms of a Reference in document order. The last
    # canonicalization transform wins; when a Reference declares none, XMLDSig
    # defaults to inclusive c14n 1.0 rather than inheriting SignedInfo's
    # canonicalization method.
    def reference_canonicalization_for(ref)
      spec = canonicalization_spec(C14N_1_0).dup

      transforms = REXML::XPath.match(
        ref,
        "./ds:Transforms/ds:Transform",
        { "ds" => DSIG }
      )

      transforms.each do |transform_element|
        algorithm = transform_element.attributes["Algorithm"]
        next unless C14N_ALGORITHMS.key?(algorithm)

        spec = C14N_ALGORITHMS[algorithm].dup
        spec[:inclusive_namespaces] = inclusive_namespaces_for(transform_element, spec)
      end

      spec
    end

    # InclusiveNamespaces only applies to exclusive c14n. For other
    # algorithms libxml2 rejects the argument, so the value is discarded.
    def inclusive_namespaces_for(element, spec)
      return nil unless spec[:mode] == Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
      return nil if element.nil?

      inclusive = REXML::XPath.first(element, "./ec:InclusiveNamespaces", { "ec" => C14N })
      return nil if inclusive.nil?

      prefix_list = inclusive.attributes.get_attribute("PrefixList")
      return nil if prefix_list.nil?

      prefix_list.value.split(/\s+/).reject(&:empty?)
    end

    # The URI of the first Reference, used to select the signed element.
    # An empty URI means the whole document; historically ruby-saml resolves
    # it to the ID of the element that contains the signature.
    def reference_id(reference_element)
      uri = reference_element.attribute("URI")
      return nil if uri.nil?

      value = uri.value
      return nil if value.nil? || value.empty?

      value.start_with?("#") ? value[1..-1] : nil
    end

    # Apply the enveloped-signature transform by deleting the Signature node
    # that is part of this signature from the referenced subtree. A signature
    # outside that subtree is not in the node-set and must remain untouched.
    def remove_enveloped_signature(nokogiri_document, rexml_signature, hashed_element)
      transforms = REXML::XPath.match(
        @ref,
        "./ds:Transforms/ds:Transform",
        { "ds" => DSIG }
      )
      return unless transforms.any? { |t| t.attributes["Algorithm"] == ENVELOPED_SIG }

      # Locate the same Signature node in the Nokogiri tree by its position
      # among all signature elements, which both parsers preserve.
      rexml_signatures = REXML::XPath.match(
        @working_copy,
        "//ds:Signature",
        { "ds" => DSIG }
      )
      signature_index = rexml_signatures.index { |node| node.equal?(rexml_signature) }
      return if signature_index.nil?

      nokogiri_signature = nokogiri_document.xpath("//ds:Signature", 'ds' => DSIG)[signature_index]
      return if nokogiri_signature.nil?
      return unless descendant_or_self?(nokogiri_signature, hashed_element)

      nokogiri_signature.remove
    end

    def descendant_or_self?(node, ancestor)
      current = node
      while current.respond_to?(:parent)
        return true if current == ancestor
        current = current.parent
      end
      false
    end

    def digests_match?(hash, digest_value)
      hash == digest_value
    end

    def extract_signed_element_id
      reference_element = REXML::XPath.first(
        self,
        "//ds:Signature/ds:SignedInfo/ds:Reference",
        {"ds"=>DSIG}
      )

      return nil if reference_element.nil?

      reference_id(reference_element) ||
        reference_element.parent.parent.parent.attribute("ID").value
    end

    # Legacy public hook: returns the prefix list of the first
    # InclusiveNamespaces in the document. Signature verification uses the
    # per-layer resolution in #canonicalization_for instead, because this
    # document-wide lookup cannot distinguish SignedInfo from Reference.
    def extract_inclusive_namespaces
      element = REXML::XPath.first(
        self,
        "//ec:InclusiveNamespaces",
        { "ec" => C14N }
      )
      if element
        prefix_list = element.attributes.get_attribute("PrefixList").value
        prefix_list.split(" ")
      else
        nil
      end
    end

  end
end
