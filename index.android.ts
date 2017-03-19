/// <reference path = "./node_modules/tns-platform-declarations/android.d.ts" />

declare var com
declare var org

let HostnameVerifier = javax.net.ssl.HostnameVerifier
let SSLContext = javax.net.ssl.SSLContext
let SSLSession = javax.net.ssl.SSLSession
let TrustManager = javax.net.ssl.TrustManager
let TrustManagerFactory = javax.net.ssl.TrustManagerFactory
let SecureRandom = java.security.SecureRandom
let HttpsURLConnection = javax.net.ssl.HttpsURLConnection
let X509TrustManager = javax.net.ssl.X509TrustManager
let X509Certificate = java.security.cert.X509Certificate
let CertificateException = java.security.cert.CertificateException
let MessageDigest = java.security.MessageDigest

let hosts: RegExp[] = []
let fingerprints = []
let env: string

@Interfaces([HostnameVerifier]) /* the interfaces that will be inherited by the resulting MyVersatileCopyWriter class */
class NativeScriptHostnameVerifier extends java.lang.Object {
    verify(hostname, session):boolean {
        return isAuthorizedHost(hostname)
    }
}

@Interfaces([javax.net.ssl.X509TrustManager]) /* the interfaces that will be inherited by the resulting MyVersatileCopyWriter class */
class NativeScriptTrustManager extends java.lang.Object {
    private defaultTrustManager: javax.net.ssl.X509TrustManager

    constructor() {
        super()
        this.defaultTrustManager = this.initializeTrustManager()
    }

    initializeTrustManager() {
        try {
            let factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(null)

            for (let index = 0; index < factory.getTrustManagers().length; index++) {
                let manager = factory.getTrustManagers()[index];
                if (manager instanceof X509TrustManager) {
                    return manager
                }
            }
        } catch (error) {
            throw new java.lang.AssertionError(error)
        }

        throw new java.lang.RuntimeException()
    }

    checkClientTrusted(chain, authType) {
        this.defaultTrustManager.checkClientTrusted(chain, authType)
    }

    checkServerTrusted(chain: java.security.cert.X509Certificate[], authType) {
        if (!isValidOID(chain[0].getSigAlgOID())) {
            throw new CertificateException()
        }

        let trustedCerts = this.defaultTrustManager.getAcceptedIssuers()

        for (let index = 0; index < chain.length; index++) {
            let cert = chain[index];
            let certPrincipal = cert.getIssuerX500Principal()

            for (let index = 0; index < trustedCerts.length; index++) {
                let trustedCert = trustedCerts[index];

                if (certPrincipal.equals(trustedCert.getIssuerX500Principal())) {
                    let fingerprint = getFingerprint(trustedCert)

                    if (isValidFingerprint(fingerprint) && env !== "production") {
                        return
                    }

                    if (isValidFingerprint(fingerprint) && env === "production") {
                        this.defaultTrustManager.checkServerTrusted(chain, authType)
                    }
                }
            }
        }

        throw new CertificateException()
    }
}

export type PinningOptions = {
    env: string
    hosts: RegExp[]
    fingerprints: string[]
}

export class SSLPinning {
    constructor(options: PinningOptions) {
        env = env
        hosts = options.hosts
        fingerprints = options.fingerprints

        Object.freeze(env)
        Object.freeze(hosts)
        Object.freeze(fingerprints)
    }
    enable() {
        let hostnameVerifier = new NativeScriptHostnameVerifier()

        try {
            let sslContext = SSLContext.getInstance('TLSv1.2')
            let trustManagers = Array.create(TrustManager, 1)
            trustManagers[0] = new NativeScriptTrustManager()
            
            // let trustManagers = [new NativeScriptTrustManager()]
            sslContext.init(null, trustManagers, new SecureRandom())

            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory())
            HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier)
            
        } catch (error) {
            throw new java.lang.RuntimeException()
        }
    }
}

function isAuthorizedHost(host: string) {
    return hosts.some(row => row.test(host))
}

function isValidFingerprint(fingerprint: string) {
    return fingerprints.some(row => row === fingerprint)
}

function getFingerprint(cert: java.security.cert.X509Certificate) {
    try {
        let messageDigest = MessageDigest.getInstance('SHA-1')
        messageDigest.update(cert.getEncoded())

        return bytesToHex(messageDigest.digest())
    } catch (error) {
        throw new java.lang.RuntimeException(error)
    }
}

function isValidOID(oID) {
    return ["1.2.840.113549.1.1.5", "1.2.840.11345.1.1.11"].indexOf(oID) != -1
}

function bytesToHex(bytes): string {
    let hex = new org.apache.commons.codec.binary.Hex()

    return hex.decode(bytes).toString()
}