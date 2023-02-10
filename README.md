# PSI implementation (WIP)

Basic implementation of ["Fast Private Set Intersection from Homomorphic Encryption"](https://dl.acm.org/doi/10.1145/3133956.3134061) by Chang et al., 2017 using [Microsoft SEAL](https://github.com/microsoft/SEAL) through [node-seal](https://github.com/morfix-io/node-seal/).

## To-do:
- [x] Implement basic, functional homomorphic PSI with no optimizations.
- [ ] Better understand the role of `polyModulusDegree` and `bitSizes`.
- [ ] Figure out what happens when sets are of bigger size.
- [ ] Better understand batching.
- [ ] Implement optimizations.