
======================================
sphinx mixnet packet crypto for golang
======================================

.. image:: https://travis-ci.org/david415/go-sphinxmixcrypto.png?branch=master
    :target: https://www.travis-ci.org/david415/go-sphinxmixcrypto
    :alt: travis for go-sphinxmixcrypto

.. image:: https://coveralls.io/repos/github/david415/go-sphinxmixcrypto/badge.svg?branch=master
  :target: https://coveralls.io/github/david415/go-sphinxmixcrypto
  :alt: coveralls for go-sphinxmixcrypto

.. image:: https://godoc.org/github.com/david415/go-sphinxmixcrypto?status.svg
  :target: https://godoc.org/github.com/david415/go-sphinxmixcrypto
  :alt: golang api docs for go-sphinxmixcrypto


what sphinx?
------------

Sphinx is a mixnet packet format.
Read the Sphinx paper:

**Sphinx: A Compact and Provably Secure Mix Format**
by George Danezis and Ian Goldberg
http://www0.cs.ucl.ac.uk/staff/G.Danezis/papers/sphinx-eprint.pdf


status
------

**currently this is an unfinished work-in-progress**

Golang Sphinx crypto implementation using modern crypto primitives;
Blake2b and Chacha20. Depends on native golang LIONESS wide block:

https://github.com/david415/go-lioness



=======
license
=======

go-sphinxmixcrypto is free software made available via the MIT License.
License details located in the LICENSE file.

Some code was inspired or copied from Lightning-Onion's partial Sphinx
implementation located here:
- https://github.com/lightningnetwork/lightning-onion/blob/master/sphinx.go

Included in this repo is Lightning-Onion's MIT License file:
LICENSE-lightening-onion


=======
contact
=======

* email dstainton415@gmail.com
* gpg key ID 0x836501BE9F27A723
* gpg fingerprint F473 51BD 87AB 7FCF 6F88  80C9 8365 01BE 9F27 A723
