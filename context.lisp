;;; Copyright (C) 2014  Ilya Khaprov https://github.com/deadtrickster
;;;
;;; See LICENSE for details.

#+xcvb
(module
 (:depends-on ("package" "conditions" "ffi" "verification")))

;; (eval-when (:compile-toplevel)
;;   (declaim
;;    (optimize (speed 3) (space 1) (safety 1) (debug 0) (compilation-speed 0))))

(in-package :cl+ssl)

(defun add-verify-files% (ssl-ctx files)
  (dolist (file files)
    (let ((namestring (if (pathnamep file) (namestring (truename file)) file)))
      (cffi:with-foreign-strings ((cafile namestring))
        (unless (eql 1 (ssl-ctx-load-verify-locations
                        ssl-ctx
                        cafile
                        (cffi:null-pointer)))
          (error "ssl-ctx-load-verify-locations failed."))))))

(defun add-verify-files (ssl-ctx files)
  (cond
    ((stringp files)
     (add-verify-files% ssl-ctx (list files)))
    ((pathnamep files)
     (add-verify-files% ssl-ctx (list files)))
    (t nil)))

(defun add-verify-pathes (ssl-ctx pathes)
  ;; (warn "not implemented")
  )

(defun create-context (&key (method *ssl-global-method*)
                            (session-cache-mode +SSL-SESS-CACHE-SERVER+)
                            (verify +SSL-VERIFY-PEER+)
                            (verify-depth 100)
                            (verify-callback (cffi:callback cb-ssl-verify))
                            (ca-files)
                            (ca-pathes)
                            (password-callback))
  (ensure-initialized)
  (let ((ssl-ctx (ssl-ctx-new method)))
    (ssl-ctx-set-session-cache-mode ssl-ctx session-cache-mode)
    (add-verify-files ssl-ctx  ca-files)
    (add-verify-pathes ssl-ctx ca-pathes)
    (ssl-ctx-set-verify-depth ssl-ctx verify-depth)
    (if verify
        (ssl-ctx-set-verify ssl-ctx verify verify-callback))
    ssl-ctx))

(defun set-context-hostname (ctx hostname)
  (cffi:with-foreign-strings ((chostname hostname))
    (ssl-ctx-set-tlsext-host-name ctx chostname)))

(defun dispose-context (ssl-ctx)
  (ssl-ctx-free ssl-ctx))
