from conans import ConanFile,tools
import os

class Solo5Conan(ConanFile):
    settings= "compiler","arch","build_type","os"
    name = "solo5"
    version = "0.4.1"
    url = "https://github.com/Solo5/solo5"
    description = "A sandboxed execution environment for unikernels. Linux only for now."
    license = "ISC"

    def source(self):
        repo = tools.Git(folder = self.name)
        repo.clone(self.url + ".git",branch="master")

    def build(self):
        self.run("CC=gcc ./configure.sh", cwd=self.name)
        self.run("make", cwd=self.name)

    def package(self):
        #grab evenrything just so its a reausable redistributable recipe
        self.copy("*.h", dst="include/solo5", src=self.name + "/include/solo5")
        self.copy("*.o", dst="lib", src=self.name + "/bindings/hvt/")
        self.copy("*.o", dst="lib", src=self.name + "/bindings/spt/")
        self.copy("solo5-hvt", dst="bin", src= self.name + "/tenders/hvt")
        self.copy("solo5-hvt-configure", dst="bin", src= self.name + "/tenders/hvt")
        self.copy("solo5-spt", dst="bin", src= self.name + "/tenders/spt")
        self.copy("solo5-spt-configure", dst="bin", src= self.name + "/tenders/spt")

    def package_info(self):
        self.env_info.path.append(os.path.join(self.package_folder, "bin"))

    def deploy(self):
        self.copy("*", dst="lib",src="lib")
        self.copy("*", dst="bin",src="bin")
        self.copy("*", dst="include", src="include")
