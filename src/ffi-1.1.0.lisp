(in-package :cl+ssl)

(cffi:defcfun ("SSL_CTX_set_default_verify_dir" ssl-ctx-set-default-verify-dir)
    :int
  (ctx :pointer))

(cffi:defcfun ("SSL_CTX_set_default_verify_file" ssl-ctx-set-default-verify-file)
    :int
  (ctx :pointer))

