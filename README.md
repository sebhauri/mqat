# MQAT

Go implementation of multivariate quadratic anonymous tokens.

⚠️ This implementation was made in the context of a proof-of-concept for a master thesis and is not ready for use in production; use it with caution. ⚠️

## Overview

- Different executables can be found in the `benchmarks` folder.
To build an executable from source, use the following command:
    ```bash
    go build -o benchmarks/<exec_name> main/main.go
    ```

- The `crypto` folder contains Go implementations of MQAT, [UOV](https://www.uovsig.org/) and [MQDSS](https://mqdss.org/).
- The `math` folder contains Go implementations of GF256, linear algebra on GF256 and computation of an homogeneous multivariate quadratic equations system.
