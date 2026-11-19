#pragma once
#include "source/common/common/logger.h"
#include "source/common/tls/cert_validator/cert_validator.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {


class MTCValidator : public CertValidator, Logger::Loggable<Logger::Id::secret> {
    public:
        MTCValidator(SslStats& stats, Server::Configuration::CommonFactoryContext& context);
        ~MTCValidator() override = default;

    absl::Status addClientValidationContext(SSL_CTX* context, bool require_client_cert) override;

    ValidationResults
    doVerifyCertChain(STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr callback,
                    const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options,
                    SSL_CTX& ssl_ctx, const ExtraValidationContext& validation_context,
                    bool is_server, absl::string_view host_name) override;
    
    absl::StatusOr<int> initializeSslContexts(std::vector<SSL_CTX*> contexts, 
                                            bool handshaker_provides_certificates,
                                            Stats::Scope& scope) override;
    
    void updateDigestForSessionId(bssl::ScopedEVP_MD_CTX& md, uint8_t hash_buffer[EVP_MAX_MD_SIZE], 
                                unsigned hash_length) override;

    std::optional<uint32_t> daysUntilFirstCertExpires() const override;
    std::string getCaFileName() const override;
    std::vector<Envoy::Ssl::CertificateDetailsPtr> getCaCertInformation() const override;

};


}
}
}
}
