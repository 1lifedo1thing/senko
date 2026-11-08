/* rsa-4096 public key of the amnezia api gateway (gw.amnezia.org).
   the official client takes it from the PROD_AGW_PUBLIC_KEY build secret, so
   it is not in its git tree. this copy was read out of the release builds
   AmneziaVPN 5.0.3.0 and 5.1.0.6 (android armeabi-v7a, libAmneziaVPN), where
   it is the same byte for byte, and the gateway answers requests sealed to it.
   der sha256 366c5a9a012aaecd10c4abdc0d63c42ee081dbb24dea1226efa8c738ba9abff5 */
static const char k_amz_gateway_pem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAj5mxl/4DL3Sk89ntxs5G\n"
    "X3JawGQWIoq6rvNkOzNGuNgedNS2+pi6hZl3Izl1Io9om4KiUlMT6mgLO1hTr9q+\n"
    "s7CYhlvroFA7ErucF+9L+7FCt0Igi0kIK/R2/vxd/2HaUrorn/aSvvutkYwbfxqW\n"
    "SwtzE+RuBeDWGvEt937OW0oqYONPYv9E4T56Dz/EZ6v2t8ejAnKLbGD/GocMmipK\n"
    "7etFSiSMAB2RmaztqTq4NleBepfO80XpYlW9pCSXuHcE8wxHczkzxsbyMAMsG/K3\n"
    "vUQY6qPtohqqzSSBwa/8u2ptNHBeor7l7DdYXeR/Nqcc4z92VUkZ5lOVR4evkS5V\n"
    "/wQqp5tnOJEj3NjUhEhXFoNEapbZd1bh6iQoUk7jC1TdvKJ/nPKGZAsHRpr0rNKz\n"
    "fx/N/Oo6lr2yh/+ps6VxTkbPmB6E85WOO3UvjImZUY0XQdBjWle/4iJLdEC77Nr0\n"
    "jXhdgeypucy6jkB6iBHMeVMlrNMEV7UxoBR/cCNx55zu/8sml5ByiDvCDT7sRomN\n"
    "NgVt5S/FaVjYuzFUifJ12ToChXFgESKFmuso7WluEaWvMIGREdrMrKQKHfYLOzWF\n"
    "2B5ZJDqw4o03fU4J/6rw61M1b+rjVpXMjPnzc2A+RgcjTvXv955gfZkwe4lt5wk/\n"
    "3j8zMVo3+zLrMTAaEeIUM0UCAwEAAQ==\n"
    "-----END PUBLIC KEY-----\n";
