#include "source/extensions/transport_sockets/tls/cert_validator/mtc/mtc_validator.h"
#include "source/common/common/macros.h"
#include "source/common/tls/cert_validator/factory.h"
#include "envoy/registry/registry.h"

namespace Envoy{
namespace Extensions{
namespace TransportSockets{
namespace Tls{  

MTCValidator::MTCValidator(SslStats& /*stats*/, Server::Configuration::CommonFactoryContext& /*context*/)
    : CertValidator(), Logger::Loggable<Logger::Id::secret>() {
    
    ENVOY_LOG(debug, "MTCValidator constructor called");
};

absl::Status MTCValidator::addClientValidationContext(SSL_CTX* context, bool require_client_cert) {
    ENVOY_LOG(debug, "MTCValidator addClientValidationContext called");
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(require_client_cert);
    return absl::OkStatus();
};

ValidationResults MTCValidator::doVerifyCertChain(STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr callback,
                    const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options,
                    SSL_CTX& ssl_ctx, const ExtraValidationContext& validation_context,
                    bool is_server, absl::string_view host_name) {
    ENVOY_LOG(debug, "MTCValidator doVerifyCertChain called");
    
    UNREFERENCED_PARAMETER(cert_chain);
    UNREFERENCED_PARAMETER(callback);
    UNREFERENCED_PARAMETER(transport_socket_options);
    UNREFERENCED_PARAMETER(ssl_ctx);
    UNREFERENCED_PARAMETER(validation_context);
    UNREFERENCED_PARAMETER(is_server);
    UNREFERENCED_PARAMETER(host_name);

    return ValidationResults{ValidationResults::ValidationStatus::Successful,
                            Envoy::Ssl::ClientValidationStatus::Validated, std::nullopt,
                            std::nullopt};  
};

absl::StatusOr<int> MTCValidator::initializeSslContexts(std::vector<SSL_CTX*>, bool, Stats::Scope&) {
    ENVOY_LOG(debug, "MTCValidator initializeSslContexts called");
    
    return SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
};


void MTCValidator::updateDigestForSessionId(bssl::ScopedEVP_MD_CTX& md, uint8_t hash_buffer[EVP_MAX_MD_SIZE], 
                                unsigned hash_length) {
    ENVOY_LOG(debug, "MTCValidator updateDigestForSessionId called");
    UNREFERENCED_PARAMETER(md);
    UNREFERENCED_PARAMETER(hash_buffer);
    UNREFERENCED_PARAMETER(hash_length);
};

std::optional<uint32_t> MTCValidator::daysUntilFirstCertExpires() const {
    ENVOY_LOG(debug, "MTCValidator daysUntilFirstCertExpires called");
    return std::nullopt;
};

std::string MTCValidator::getCaFileName() const {
    ENVOY_LOG(debug, "MTCValidator getCaFileName called");
    return "";
};

std::vector<Envoy::Ssl::CertificateDetailsPtr> MTCValidator::getCaCertInformation() const {
    ENVOY_LOG(debug, "MTCValidator getCaCertInformation called");
    return {};
};

class MTCValidatorFactory : public CertValidatorFactory {
public:
    absl::StatusOr<CertValidatorPtr>
    createCertValidator(const Envoy::Ssl::CertificateValidationContextConfig* /*config*/, SslStats& stats,
                      Server::Configuration::CommonFactoryContext& context,
                      Stats::Scope& /*scope*/) override {
        ENVOY_LOG_MISC(debug, "MTCValidatorFactory createCertValidator called");
        auto validator = std::make_unique<MTCValidator>(stats, context);
        return validator;
    }
    std::string name() const override { return "envoy.tls.cert_validator.mtc"; }

};

REGISTER_FACTORY(MTCValidatorFactory, CertValidatorFactory);


} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy