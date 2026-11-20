Real files of a real Conan 2.21.0 client (`conan create` and `conan upload` of the recipe `hello-recipe.py`, a header-only library with
the header `hello.h`, as `hello/1.0` in a Release and a Debug binary and as `hello/2.0` in one binary), kept as the recording remote
(`../conan_recorder.py`) laid them out: `{name}/{version}/_/_/revisions/{rrev}/...` and `.../packages/{pkgid}/revisions/{prev}/...`.
The fake ConanCenter (`../fakes/conan.mjs`, `publish`) serves them with the times a scenario chooses.
