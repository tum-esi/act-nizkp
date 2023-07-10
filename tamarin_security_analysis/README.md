# act-nizkp-security-analysis
Formal security analysis using [Tamarin-Prover](https://tamarin-prover.github.io/) for the non-interactive zero-knowledge protocol: ACT.

## Tamarin-Prover
+ [Tamarin-Prover](https://tamarin-prover.github.io/) is a tool used for the formal security analysis of security protocols. More details on how to install Tamarin is avaialable [here](https://tamarin-prover.github.io/manual/book/002_installation.html#:~:text=Installation%201%20Installation%20on%20macOS%20or%20Linux%20The,...%205%20Tamarin%20Code%20Editors%20...%20Weitere%20Elemente).
+ You can run Tamarin on our models using the following steps:
    1. Run: `tamarin-prover interactive nizk_transformation.spthy`
    1. A link will appear in your console. Open the link in the browser and click on the file you want to analyse. 
    1. Click on `sorry`.
    1. Click on `autoprove (S. for all solutions) for all lemmas`.
+ More information about Tamarin-Prover is avaialble [here](https://tamarin-prover.github.io/manual/book/001_introduction.html).