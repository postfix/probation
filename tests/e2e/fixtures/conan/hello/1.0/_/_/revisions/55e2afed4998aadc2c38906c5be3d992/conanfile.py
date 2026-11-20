from conan import ConanFile
from conan.tools.files import copy


class HelloConan(ConanFile):
    name = "hello"
    package_type = "header-library"
    exports_sources = "include/*"
    settings = "build_type"

    def package(self):
        copy(self, "*.h", self.source_folder, self.package_folder)
