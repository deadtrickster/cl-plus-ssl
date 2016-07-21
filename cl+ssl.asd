;;; -*- mode: lisp -*-
;;;
;;; Copyright (C) 2001, 2003  Eric Marsden
;;; Copyright (C) 2005  David Lichteblau
;;; Copyright (C) 2007  Pixel // pinterface
;;; "the conditions and ENSURE-SSL-FUNCALL are by Jochen Schmidt."
;;;
;;; See LICENSE for details.

(defpackage :cl+ssl-system
  (:use :cl :asdf))

(in-package :cl+ssl-system)

(defsystem :cl+ssl
  :description "Common Lisp interface to OpenSSL."
  :license "MIT"
  :author "Eric Marsden, Jochen Schmidt, David Lichteblau"
  :depends-on (:cffi :uiop :babel :trivial-gray-streams :flexi-streams
               :bordeaux-threads :trivial-garbage #+sbcl :sb-posix)
  :serial t
  :components ((:module "src"
                :serial t
                :components
                ((:file "package")
                 (:file "reload")
                 (:file "conditions")
                 (:file "ffi")
                 (:file "ffi-1.1.0")
                 (:file "x509")
                 (:file "ffi-buffer-all")
                 #-clisp (:file "ffi-buffer")
                 #+clisp (:file "ffi-buffer-clisp")
                 (:file "streams")
                 (:file "bio")
                 (:file "random")
                 (:file "context")
                 (:file "verify-hostname")))))
