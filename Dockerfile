FROM digitalsleuth/remnux-build:latest

LABEL version="1.9"
LABEL description="REMnux Docker based on Ubuntu 18.04 LTS"
LABEL maintainer="https://github.com/digitalsleuth/remnux-docker"

ENV TERM linux
ENV DEBIAN_FRONTEND noninteractive
ENV PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

#CLONES
RUN git clone --depth 1 https://github.com/vivisect/vivisect /vivisect && \
cd /tmp && \
git clone --depth 1 https://github.com/10110111/gdtoa-desktop /tmp/gdtoa-desktop && \
git clone --depth 1 --recursive https://github.com/eteran/edb-debugger /tmp/edb-debugger && \
git clone --depth 1 https://github.com/guelfoweb/peframe /tmp/peframe && \
git clone --depth 1 https://github.com/buffer/ioc_parser.git /tmp/ioc_parser && \
git clone --depth 1 https://github.com/buffer/libemu.git /tmp/libemu && \
git clone --depth 1 https://github.com/rjhansen/nsrllookup /tmp/nsrllookup && \
hg clone https://bitbucket.org/cybertools/disass /tmp/disass && \
git clone --depth 1 https://github.com/area1/stpyv8 /tmp/stpyv8 && \
git clone --depth 1 https://github.com/buffer/thug /tmp/thug && \
git clone --depth 1 https://github.com/fireeye/flashmingo /usr/share/flashmingo && rm -rf /usr/share/flashmingo/.git && \
git clone --depth 1 https://github.com/FortyNorthSecurity/just-metadata /usr/share/just-metadata && rm -rf /usr/share/just-metadata/.git && \
git clone --depth 1 https://github.com/1aN0rmus/TekDefense-Automater.git /usr/share/automater && rm -rf /usr/share/automater/.git && \
git clone --depth 1 https://github.com/merces/bashacks /tmp/bashacks && \
git clone --depth 1 https://github.com/omriher/captipper /usr/share/captipper && rm -rf /usr/share/captipper/.git && \
git clone --depth 1 https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP.git /tmp/DC3-MWCP && \
git clone --depth 1 https://github.com/DidierStevens/DidierStevensSuite /tmp/didier && \
git clone --depth 1 https://github.com/USArmyResearchLab/dshell /usr/share/dshell && rm -rf /usr/share/dshell/.git && \
git clone --depth 1 https://github.com/mandiant/ioc_writer /tmp/ioc_writer && \
git clone --depth 1 https://github.com/jtpereyda/libdasm /tmp/libdasm && \
git clone --depth 1 https://github.com/KoreLogicSecurity/mastiff /tmp/mastiff && \
git clone --depth 1 https://github.com/herumi/cybozulib /tmp/cybozulib && \
git clone --depth 1 https://github.com/herumi/msoffice /tmp/msoffice && \
git clone --depth 1 https://github.com/grierforensics/officedissector /tmp/officedissector && \
git clone --depth 1 https://github.com/9b/pdfxray_lite /usr/local/bin/pdfxray_lite && rm -rf /usr/local/bin/pdfxray_lite/.git && \
git clone --depth 1 --recursive https://github.com/merces/pev /tmp/pev && \
git clone --depth 1 https://github.com/zrax/pycdc /tmp/pycdc && \
git clone --depth 1 https://github.com/digitalsleuth/pyfuzzy /tmp/pyfuzzy && \
git clone --depth 1 https://github.com/digitalsleuth/inlineegg /tmp/inlineegg && \
git clone --depth 1 https://github.com/CyberShadow/RABCDASm.git /tmp/RABCDASm && \
git clone --depth 1 https://github.com/kevthehermit/RATDecoders /tmp/RATDecoders && \
git clone --depth 1 https://github.com/digitalsleuth/color_ssh_terminal /tmp/colorssh && \
git clone --depth 1 https://github.com/HynekPetrak/malware-jail.git /tmp/malware-jail

#gdtoa-desktop
RUN cd /tmp/gdtoa-desktop && \
mkdir build && cd build && cmake .. && make && make install && \
cd /tmp && rm -rf gdtoa-desktop && \
\
#edb-debugger
cd /tmp/edb-debugger && \
mkdir build && cd build && cmake -DCMAKE_INSTALL_PREFIX=/usr/local/ .. && make && make install && \
ln -s /usr/local/lib/libgdtoa-desktop.so /usr/lib/libgdtoa-desktop.so && \
cd /tmp && rm -rf edb-debugger && \
\
#peframe
cd /tmp/peframe && pip3 install -r requirements.txt && python3 setup.py install && \
cd /tmp && rm -rf peframe && \
\
#Flare-Fakenet
pip install https://github.com/fireeye/flare-fakenet-ng/zipball/master && \
wget -q https://github.com/leibnitz27/cfr/releases/download/0.149/cfr-0.149.jar -O /usr/local/bin/cfr.jar && \
cd /tmp/ioc_parser && python3 setup.py build && python3 setup.py install && \
cd /tmp && rm -rf ioc_parser/ && \
\
#LIBEMU
cd /tmp/libemu && autoreconf -v -i && \
./configure && make && make install > /dev/null && \
cd /tmp && rm -rf libemu/ && pip3 install pylibemu && \
\
#FLARE-FLOSS
wget -q https://github.com/fireeye/flare-floss/releases/download/v1.5.0/floss-1.5.0-GNU.Linux.zip -O /tmp/floss.zip && \
unzip -d /usr/local/bin /tmp/floss.zip && \
chmod +x /usr/local/bin/floss && rm /tmp/floss.zip && \
\
#JAD
wget -q https://varaneckas.com/jad/jad158e.linux.static.zip -O /tmp/jad.zip && \
unzip -d /usr/local/bin /tmp/jad.zip && \
rm /tmp/jad.zip && \
\
#NSRLLookup
cd /tmp/nsrllookup && cmake . && make && make install && \
cd /tmp && rm -rf nsrllookup && \
\
#disass
cd disass && python setup.py install > /dev/null && \
cd /tmp && rm -rf disass/ && \
\
#STPYV8 and Thug
cd stpyv8 && \
python2 setup.py v8 > /dev/null && \
python3 setup.py stpyv8 > /dev/null && \
python3 setup.py install > /dev/null && \
cd /tmp && rm -rf stpyv8 && \
cd thug && python3 setup.py build && \
python3 setup.py install && \
cd /tmp && rm -rf thug && \

#vivisect
ln -s /vivisect/vivbin /usr/local/bin/vivbin && \
ln -s /vivisect/vdbbin /usr/local/bin/vdbbin && \
rm -rf /vivisect/.git && \
\
#elfparser
wget -q http://elfparser.com/release/elfparser_x86_64_1.4.0.deb -O /tmp/elfparser.deb && dpkg -i /tmp/elfparser.deb && \
rm /tmp/elfparser.deb && \
\
#signsrch
wget -q http://aluigi.altervista.org/mytoolz/signsrch.zip -O /tmp/signsrch.zip && unzip /tmp/signsrch.zip -d /tmp/signsrch && \
cd /tmp/signsrch && mkdir /usr/share/signsrch && cp signsrch.sig /usr/share/signsrch/ && cd src && make && make install && \
cd /tmp && rm -rf signsrch && rm /tmp/signsrch.zip && \

#MALWARE-CRAWLER INSTALL - NEEDS WORK - Determine if necessary
#IF using pymongo>=3, Must edit core/database.py and change line 14 from:
#from pymongo.connection import Connection
#to:
#from pymongo import MongoClient as Connection
#RUN apt-get -qq install -y python-jsonpickle python-m2crypto python-bitstring && \
#pip install pymongo BeautifulSoup Jinja2 && \
#cd /tmp && git clone --depth 1 https://github.com/evilcry/malware-crawler && mv malware-crawler /usr/share/ && \
#ln -s /usr/share/malware-crawler/MalwareCrawler/src/ragpicker.py /usr/local/bin/ragpicker.py

#Flare (Flash File Parsing)
wget -q http://www.nowrap.de/download/flare06linux64.tgz -O /tmp/flare.tgz && mkdir /usr/share/flare/ && \
tar -C /usr/share/flare/ -xf /tmp/flare.tgz && ln -s /usr/share/flare/flare /usr/local/bin/flare && \
rm /tmp/flare.tgz && \
\
#Flashmingo
cd /usr/share/flashmingo && \
pip3 install -r requirements.txt && sed -i '1 i\#!/usr/bin/python3' flashmingo-cmd.py && \
ln -s /usr/share/flashmingo/flashmingo-cmd.py /usr/local/bin/flashmingo.py && \
sed -i 's/plugins_dir: plugins/plugins_dir: \/usr\/share\/flashmingo\/plugins/g' /usr/share/flashmingo/cfg.yml && \
sed -i "s/self.config_file = 'cfg.yml'/self.config_file = '\/usr\/share\/flashmingo\/cfg.yml'/g" /usr/share/flashmingo/flashmingo/Flashmingo.py && \
\
#Just-Metadata
ln -s /usr/share/just-metadata/JustMetadata.py /usr/local/bin/justmetadata.py && \
\
#XOR Search and XOR Strings (Didier Stevens)
wget -q http://didierstevens.com/files/software/XORSearch_V1_11_2.zip -O /tmp/xorsearch.zip && \
wget -q http://didierstevens.com/files/software/XORStrings_V0_0_1.zip -O /tmp/xorstrings.zip && \
unzip -p /tmp/xorstrings.zip XORStrings.c > /tmp/xorstrings.c && gcc -o /usr/local/bin/xorstrings /tmp/xorstrings.c && \
rm /tmp/xorstrings.c && \
unzip -d /tmp/xorsearch /tmp/xorsearch.zip && mv /tmp/xorsearch/Linux/xorseach-x64-dynamic /usr/local/bin/xorsearch && \
chmod +x /usr/local/bin/xorsearch && cd /tmp && rm -rf xorsearch && rm xors*.zip && \
\
#TekDefense-Automater and Andro requirements
pip3 install androguard && export LC_ALL=C.UTF-8 && export LANG=C.UTF-8 && pip3 install androwarn && \
ln -s /usr/share/automater/Automater.py /usr/local/bin/automater.py && chmod +x /usr/local/bin/automater.py && \
\
#Bashacks
cd /tmp/bashacks && make && mkdir /usr/share/bashacks && mv bashacks.sh /usr/share/bashacks/ && \
cd /tmp && rm -rf bashacks && \

#BUILD CUTTER vice DOWNLOAD
#RUN apt-get -qq install -y libzip-dev zlib1g-dev && pip3 install meson && ln -s /usr/local/bin/meson /usr/bin/meson && cd /tmp && \
#git clone --recurse-submodules https://github.com/radareorg/cutter && cd cutter && \
#mkdir build && cd build && cmake -DCUTTER_USE_BUNDLED_RADARE2=ON -DCMAKE_EXE_LINKER_FLAGS="-Wl,--disable-new-dtags" ../src && cmake --build .

#CUTTER
wget -q https://github.com/radareorg/cutter/releases/download/v1.10.1/Cutter-v1.10.1-x64.Linux.AppImage -O /tmp/cutter && \
chmod +x /tmp/cutter && cd /tmp && ./cutter --appimage-extract && mv squashfs-root /usr/share/cutter && \
ln -s /usr/share/cutter/AppRun /usr/local/bin/cutter && chmod +x /usr/share/cutter/AppRun && rm /tmp/cutter && \
\
#ByteHist
wget -q https://www.cert.at/media/files/downloads/software/bytehist/files/bytehist_1_0_102_linux.zip -O /tmp/bytehist.zip && \
unzip -p /tmp/bytehist.zip lin64/bytehist > /usr/local/bin/bytehist && chmod +x /usr/local/bin/bytehist && \
rm /tmp/bytehist.zip && \
\
#Captipper
ln -s /usr/share/captipper/CapTipper.py /usr/local/bin/captipper.py && chmod +x /usr/share/captipper/CapTipper.py && \
\
#DC3-MWCP
pip3 install /tmp/DC3-MWCP && \
cd /tmp && rm -rf /tmp/DC3-MWCP && \
\
#Densityscout
wget -q https://www.cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_linux.zip -O /tmp/densityscout.zip && \
unzip -p /tmp/densityscout.zip lin64/densityscout > /usr/local/bin/densityscout && chmod +x /usr/local/bin/densityscout && \
rm /tmp/densityscout.zip && \
\
#DIE - Detect It Easy
wget -q https://github.com/horsicq/DIE-engine/releases/download/2.05/die_lin64_portable_2.05.tar.gz -O /tmp/die.tar.gz && \
mkdir /usr/share/die && tar -C /usr/share/die/ -xf /tmp/die.tar.gz && \
ln -s /usr/share/die/die.sh /usr/local/bin/die.sh && ln -s /usr/share/die/diec.sh /usr/local/bin/diec.sh && \
ln -s /usr/share/die/diel.sh /usr/local/bin/diel.sh && rm /tmp/die.tar.gz && \
\
#DidierStevens Suite
cd /tmp/didier && \
for i in $(find . -type f | egrep  ".py" | sed 's/\.\///g' | sort ); do chmod +x $i; done && \
for i in $(find . -type f | egrep  ".py|.yara|.ini" | sed 's/\.\///g' | sort); do mv $i /usr/local/bin; done && \
chmod +x Linux/js-file Linux/js-ascii Linux/js && mv Linux/js Linux/js-didier && \
mv Linux/js-file Linux/js-ascii Linux/js-didier /usr/local/bin/ && \
cd /tmp && rm -rf didier && \
\
#DShell
cd /usr/share/dshell && make && \
ln -s /usr/share/dshell/dshell /usr/local/bin/dshell && chmod +x /usr/share/dshell/dshell && \
\
#findaes
wget -q https://iweb.dl.sourceforge.net/project/findaes/findaes-1.2.zip -O /tmp/findaes.zip && \
unzip -d /tmp/findaes -j /tmp/findaes.zip && cd /tmp/findaes && make && mv findaes /usr/local/bin && \
cd /tmp && rm -rf findaes && rm findaes.zip && \
\
#IOC Writer
cd /tmp/ioc_writer && python setup.py install && \
cd /tmp && rm -rf ioc_writer && \

#JD-GUI - requires xdg-utils
wget -q https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.deb -O /tmp/jdgui.deb && \
dpkg -i /tmp/jdgui.deb && rm /tmp/jdgui.deb && mv /opt/jd-gui /usr/share/ && \
\
#LIBDasm
cd /tmp/libdasm && make && make install && \
ln -s /usr/local/lib/libdasm.so.1.0 /lib/x86_64-linux-gnu/libdasm.so.1 && \
cd /tmp && rm -rf libdasm && \
\
#Mastiff
cd /tmp/mastiff && \
sed -i "s/'Yapsy == 1.10, !=1.10-python3'/'yapsy'/g" setup.py && python setup.py install && \
cd /tmp && rm -rf mastiff && \
\
#MS Office Encrypt Decrypt Attack
mkdir /tmp/work && cd /tmp/msoffice && \
make -j RELEASE=1 && mv bin/msoffice-crypt.exe /usr/local/bin/msoffice-crypt && mv bin/attack.exe /usr/local/bin/attack && \
cd /tmp && rm -rf msoffice cybozulib && \
\
#NetworkMiner
wget -q https://www.netresec.com/?download=NetworkMiner -O /tmp/nm.zip && \
unzip /tmp/nm.zip -d /opt/ && cd /opt/NetworkMiner* && chmod +x NetworkMiner.exe && chmod -R go+w AssembledFiles/ && chmod -R go+w Captures/ && \
cd /tmp && rm nm.zip && \
\
#Office Dissector
pip install /tmp/officedissector && mkdir /etc/mastiff/plugins && \
cd /tmp/officedissector && mv mastiff-plugins /etc/mastiff/plugins/Office && \
sed -i -e '0,/plugin_dir = /! {0,/plugin_dir = / s/plugin_dir = /plugin_dir = \/etc\/mastiff\/plugins\/Office, \/etc\/mastiff\/plugins/}' /etc/mastiff/mastiff.conf && \
cat /etc/mastiff/plugins/Office/magic-ooxml >> /etc/magic && \
cd /tmp && rm -rf officedissector && \
\
#pdfxray_lite
cd /usr/local/bin/pdfxray_lite && sed -i '1 i\#!/usr/bin/python2\n' swf_mastah.py && \
sed -i '1 i\#!/usr/bin/python2\n' pdfxray_lite.py && \
ln -s /usr/local/bin/pdfxray_lite/pdfxray_lite.py /usr/local/bin/pdfxray_lite.py && \
ln -s /usr/local/bin/pdfxray_lite/swf_mastah.py /usr/local/bin/swf_mastah.py && \
\
#pev
cd /tmp/pev && make && make install && ldconfig && \
cd /tmp && rm -rf pev && \
\
#PortexAnalyzer and Maldet
mkdir /usr/share/portex && wget -q https://github.com/katjahahn/PortEx/raw/master/progs/PortexAnalyzer.jar -O /usr/share/portex/PortexAnalyzer.jar && \
wget -q https://github.com/katjahahn/PortEx/raw/master/progs/maldet.jar -O /usr/share/portex/maldet.jar && \

#Procdot - requires libwebkitgtk-3.0-dev
wget -q https://www.procdot.com/download/procdot/binaries/procdot_1_22_57_linux.zip -O /tmp/procdot.zip && unzip -d /tmp/procdot /tmp/procdot.zip && \
cd /tmp/procdot && chmod +x lin64/proc* && mv lin64 /usr/share/procdot && \
ln -s /usr/share/procdot/procdot /usr/local/bin/procdot && ln -s /usr/share/procdot/procmon2dot /usr/local/bin/procmon2dot && \
cd /tmp && rm -rf procdot && rm procdot.zip && \
\
#pycdc
cd /tmp/pycdc && cmake CMakeLists.txt && make && make install && \
cd /tmp && rm -rf pycdc && \
\
#Pyfuzzy
cd /tmp/pyfuzzy && \
python setup.py install && \
cd /tmp && rm -rf pyfuzzy && \
\
#Chilkat2
wget -q https://chilkatdownload.com/9.5.0.82/chilkat2-9.5.0-python-3.6-x86_64-linux.tar.gz -O /tmp/ck2.tar.gz && \
tar -xf /tmp/ck2.tar.gz --one-top-level=/tmp/ck2 --strip 1 && cd /tmp/ck2 && python3 installChilkat.py && \
cd /tmp && rm ck2.tar.gz && rm -rf ck2 && \
\
#InlineEgg
cd /tmp/inlineegg && python setup.py install && \
cd /tmp && rm -rf inlineegg && \
\
#python-pdns not installed at this time, looking to update/refactor a few things.
\
#DMD required to build RABCDasm, removed after usage.
wget -q http://downloads.dlang.org/releases/2.x/2.091.0/dmd_2.091.0-0_amd64.deb -O /tmp/dmd.deb && \
dpkg -i /tmp/dmd.deb && cd /tmp/RABCDASm && dmd -run build_rabcdasm.d && \
mv rabcdasm rabcasm abcexport abcreplace swfdecompress swf7zcompress swflzmacompress swfbinexport swfbinreplace /usr/local/bin/ && \
cd /tmp && rm -rf RABCDASm && apt-get remove dmd -y && rm dmd.deb && \
\
#RATDecoders/malconf - Readme has non-ascii character in it causing issue with install
cd /tmp/RATDecoders && echo "" > README.md && \
pip3 install -r requirements.txt && python3 setup.py install && \
cd /tmp && rm -rf RATDecoders && \
\
#MalwareJail - Removes all malware samples from the git clone as well
cd /tmp/malware-jail && npm audit fix --force && npm install && cd malware && rm -rf * && \
cd /tmp && mv malware-jail /usr/share && \
\
apt-get autoremove -y && apt-get purge && apt-get clean

RUN echo "On the Options - Preferences - Directories tab of edb, change Plugin Directory to /usr/local/lib/edb to fix the Debugger Core Error" > /home/remnux/EDB_ERROR_FIX.txt && \
cd /tmp/colorssh && cat color_ssh_terminal >> /home/remnux/.bashrc && cd /tmp && rm -rf colorssh && \
echo "[[ -e /usr/share/bashacks/bashacks.sh ]] && source /usr/share/bashacks/bashacks.sh" >> /home/remnux/.bash_profile && \
echo alias cfr=\'java -jar /usr/local/bin/cfr.jar\' >> /home/remnux/.bashrc && \
echo alias jd-gui=\'java -jar /usr/share/jd-gui/jd-gui.jar\' >> /home/remnux/.bashrc && \
echo alias networkminer=\'mono /opt/NetworkMiner*/NetworkMiner.exe --noupdatecheck\' >> /home/remnux/.bashrc && \
echo alias portex=\'java -jar /usr/share/portex/PortexAnalyzer.jar\' >> /home/remnux/.bashrc && \
echo alias maldet=\'java -jar /usr/share/portex/maldet.jar\' >> /home/remnux/.bashrc && \
echo alias jailme=\'cd /usr/share/malware-jail && node jailme.js\' >> /home/remnux/.bashrc && \
echo source .bashrc >> /home/remnux/.bash_profile && \
chown remnux:remnux /home/remnux/.bashrc

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
