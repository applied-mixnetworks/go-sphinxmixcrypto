
======================================
sphinx mixnet packet crypto for golang
======================================

.. image:: https://travis-ci.org/applied-mixnetworks/go-sphinxmixcrypto.png?branch=master
    :target: https://www.travis-ci.org/applied-mixnetworks/go-sphinxmixcrypto
    :alt: travis for go-sphinxmixcrypto

.. image:: https://coveralls.io/repos/github/applied-mixnetworks/go-sphinxmixcrypto/badge.svg?branch=master
  :target: https://coveralls.io/github/applied-mixnetworks/go-sphinxmixcrypto
  :alt: coveralls for go-sphinxmixcrypto

.. image:: https://godoc.org/github.com/applied-mixnetworks/go-sphinxmixcrypto?status.svg
  :target: https://godoc.org/github.com/applied-mixnetowrks/go-sphinxmixcrypto
  :alt: golang api docs for go-sphinxmixcrypto


Warning
=======
This code has not been formally audited by a cryptographer. It therefore should not
be considered safe or correct. Use it at your own risk! (however test vectors are verified using
other language implementations: rust, golang, python trinity!)


details
-------

Read the Sphinx paper:

**Sphinx: A Compact and Provably Secure Mix Format**
by George Danezis and Ian Goldberg

- http://www0.cs.ucl.ac.uk/staff/G.Danezis/papers/sphinx-eprint.pdf


status
------

This package is binary compatible with the python library:

- https://github.com/david415/sphinxmixcrypto

The two libraries share unit test vectors to prove that they are binary compatible.


dependencies
------------

You can see a list of dependencies on godocs:

- https://godoc.org/github.com/david415/go-sphinxmixcrypto?imports

Currently this library depends on my own LIONESS wide block cipher implementation:

- https://github.com/david415/go-lioness

The other external dependencies include:

- https://git.schwanenlied.me/yawning/chacha20
- https://github.com/minio/blake2b-simd
- https://golang.org/x/crypto/curve25519


=======
license
=======

go-sphinxmixcrypto is free software made available via the MIT License.
License details located in the LICENSE file.

Some code was inspired or copied from Lightning-Onion's partial Sphinx
implementation located here:

- https://github.com/lightningnetwork/lightning-onion/blob/master/sphinx.go
- https://github.com/lightningnetwork/lightning-onion/blob/master/sphinx_test.go

Included in this repo is Lightning-Onion's MIT License file:
LICENSE-lightening-onion


=======
contact
=======

* email dstainton415@gmail.com
* gpg key ID 0x836501BE9F27A723
* gpg fingerprint F473 51BD 87AB 7FCF 6F88  80C9 8365 01BE 9F27 A723
