FROM jaraco/multipy-tox

RUN py -m pip install pytest
WORKDIR src
CMD py -m pytest
