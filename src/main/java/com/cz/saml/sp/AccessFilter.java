package com.cz.saml.sp;


import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.cz.saml.OpenSAMLUtils;
import com.cz.saml.idp.IDPConstants;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;

public class AccessFilter implements Filter {

    private static Logger logger = LoggerFactory.getLogger(AccessFilter.class);

    private static final String MESSAGE_RECEIVER_ENDPOINT = "http://localhost:8080/opensaml-signing-and-verification/receiverPage";
    private static final String ASSERTION_CONSUMER_ENDPOINT = "The should be the endpoint that should recieve the result of the authentication";
    private static final String ISSUER = "This should be the sender entityId";
    private static final String KEY_STORE_PASSWORD = "password";
    private static final String KEY_STORE_ENTRY_PASSWORD = "password";
    private static final String KEY_STORE_PATH = "/senderKeystore.jks";
    private static final String ENTITY_ID = "sender.example.com";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
        try {
            javaCryptoValidationInitializer.init();

            for (Provider jceProvider : Security.getProviders()) {
                logger.info(jceProvider.getInfo());
            }

            XMLObjectProviderRegistry registry = new XMLObjectProviderRegistry();
            ConfigurationService.register(XMLObjectProviderRegistry.class, registry);

            registry.setParserPool(getParserPool());

            logger.info("Initializing");
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException("Initialization failed");
        }

    }

    private static ParserPool getParserPool() {
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(100);
        parserPool.setCoalescing(true);
        parserPool.setIgnoreComments(true);
        parserPool.setIgnoreElementContentWhitespace(true);
        parserPool.setNamespaceAware(true);
        parserPool.setExpandEntityReferences(false);
        parserPool.setXincludeAware(false);

        final Map<String, Boolean> features = new HashMap<String, Boolean>();
        features.put("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);
        features.put("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
        features.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
        features.put("http://apache.org/xml/features/validation/schema/normalized-value", Boolean.FALSE);
        features.put("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);

        parserPool.setBuilderFeatures(features);

        parserPool.setBuilderAttributes(new HashMap<String, Object>());

        try {
            parserPool.initialize();
        } catch (ComponentInitializationException e) {
            logger.error(e.getMessage(), e);
        }

        return parserPool;
    }


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;

        if (httpServletRequest.getSession().getAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE) != null) {
            filterChain.doFilter(servletRequest, servletResponse);
        } else {
            setGotoURLOnSession(httpServletRequest);
            redirectUserForAuthentication(httpServletResponse);
        }



    }

    private void setGotoURLOnSession(HttpServletRequest request) {
        request.getSession().setAttribute(SPConstants.GOTO_URL_SESSION_ATTRIBUTE, request.getRequestURL().toString());
    }

    private void redirectUserForAuthentication(HttpServletResponse httpServletResponse) {
        AuthnRequest authnRequest = buildAuthnRequest();
        redirectUserWithRequest(httpServletResponse, authnRequest);

    }

    private void redirectUserWithRequest(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {


        MessageContext context = new MessageContext();

        context.setMessage(authnRequest);

        SAMLBindingContext bindingContext = context.getSubcontext(SAMLBindingContext.class, true);
        bindingContext.setRelayState("teststate");

        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);

        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(getIPDEndpoint());

        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
        signatureSigningParameters.setSigningCredential(SPCredentials.getCredential());
        signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

        context.getSubcontext(SecurityParametersContext.class, true)
                .setSignatureSigningParameters(signatureSigningParameters);

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();

        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(httpServletResponse);

        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        logger.info("AuthnRequest: ");
        OpenSAMLUtils.logSAMLObject(authnRequest);

        logger.info("Redirecting to IDP");
        try {
            encoder.encode();
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private AuthnRequest buildAuthnRequest() {
        AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(Instant.now());
        authnRequest.setDestination(getIPDSSODestination());
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerEndpoint());
        authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
        authnRequest.setIssuer(buildIssuer());
        authnRequest.setNameIDPolicy(buildNameIdPolicy());
        authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());

        return authnRequest;
    }

    private RequestedAuthnContext buildRequestedAuthnContext() {
        RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        AuthnContextClassRef passwordAuthnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setURI(AuthnContext.PASSWORD_AUTHN_CTX);

        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

        return requestedAuthnContext;

    }

    private NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);

        nameIDPolicy.setFormat(NameIDType.TRANSIENT);

        return nameIDPolicy;
    }

    private Issuer buildIssuer() {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(getSPIssuerValue());

        return issuer;
    }

    private String getSPIssuerValue() {
        return SPConstants.SP_ENTITY_ID;
    }

    private String getAssertionConsumerEndpoint() {
        return SPConstants.ASSERTION_CONSUMER_SERVICE;
    }

    private String getIPDSSODestination() {
        return IDPConstants.SSO_SERVICE;
    }

    private Endpoint getIPDEndpoint() {
        SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation(getIPDSSODestination());

        return endpoint;
    }




    @Override
    public void destroy() {

    }
}
