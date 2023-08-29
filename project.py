import os
import subprocess

from sipbuild import Project


class AnalizatorProject(Project):
    def _build_analizator(self):
        cwd = os.path.abspath('analizator')
        print(cwd)
        subprocess.run(['make'], cwd=cwd, capture_output=True, check=True)

    def build(self):
        self._build_analizator()
        super().build()

    def build_sdist(self, sdist_directory):
        self._build_analizator()
        return super().build_sdist(sdist_directory)

    def build_wheel(self, wheel_directory):
        self._build_analizator()
        return super().build_wheel(wheel_directory)

    def install(self):
        self._build_analizator()
        super().install()


create = AnalizatorProject()
create.build()
create.build_sdist('')
create.build_wheel('')
create.install()
