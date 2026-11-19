load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_extension(
    name = "config",
    srcs = ["mtc_validator.cc"],
    hdrs = ["mtc_validator.h"],
    external_deps = ["ssl"],
    deps = [
        "//source/common/common:minimal_logger_lib",
        "//source/common/tls/cert_validator:cert_validator_lib",
        "//source/common/common:macros",
        "//envoy/registry:registry",
    ],
)