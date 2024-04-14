#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux
CND_DLIB_EXT=so
CND_CONF=Debug
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/AES.o \
	${OBJECTDIR}/AVLTree.o \
	${OBJECTDIR}/Amortized3.o \
	${OBJECTDIR}/AmortizedBASClient.o \
	${OBJECTDIR}/AmortizedBASServer.o \
	${OBJECTDIR}/AmortizedNlogN.o \
	${OBJECTDIR}/AmortizedOneChoice.o \
	${OBJECTDIR}/AmortizedPiBAS.o \
	${OBJECTDIR}/AmortizedTwoChoice.o \
	${OBJECTDIR}/Bid.o \
	${OBJECTDIR}/DeAmortizedBASClient.o \
	${OBJECTDIR}/DeAmortizedBASServer.o \
	${OBJECTDIR}/DeAmortizedSDdBAS.o \
	${OBJECTDIR}/DeAmortizedSDdGeneral.o \
	${OBJECTDIR}/DeAmortizedSDdNlogN.o \
	${OBJECTDIR}/DeAmortizedSDdPlaintext.o \
	${OBJECTDIR}/NlogNClient.o \
	${OBJECTDIR}/NlogNSDdGeneralClient.o \
	${OBJECTDIR}/NlogNServer.o \
	${OBJECTDIR}/NlogNStorage.o \
	${OBJECTDIR}/NlogNWithOptimalLocalityClient.o \
	${OBJECTDIR}/NlogNWithOptimalLocalityServer.o \
	${OBJECTDIR}/NlogNWithOptimalLocalityStorage.o \
	${OBJECTDIR}/NlogNWithTunableLocalityClient.o \
	${OBJECTDIR}/NlogNWithTunableLocalityServer.o \
	${OBJECTDIR}/NlogNWithTunableLocalityStorage.o \
	${OBJECTDIR}/OMAP.o \
	${OBJECTDIR}/ORAM.o \
	${OBJECTDIR}/OneChoiceClient.o \
	${OBJECTDIR}/OneChoiceSDdGeneralClient.o \
	${OBJECTDIR}/OneChoiceSDdGeneralServer.o \
	${OBJECTDIR}/OneChoiceSDdNoOMAPClient.o \
	${OBJECTDIR}/OneChoiceSDdNoOMAPServer.o \
	${OBJECTDIR}/OneChoiceSDdNoOMAPStorage.o \
	${OBJECTDIR}/OneChoiceSDdOMAPClient.o \
	${OBJECTDIR}/OneChoiceSDdOMAPServer.o \
	${OBJECTDIR}/OneChoiceSDdOMAPStorage.o \
	${OBJECTDIR}/OneChoiceServer.o \
	${OBJECTDIR}/OneChoiceStorage.o \
	${OBJECTDIR}/RAMStore.o \
	${OBJECTDIR}/Server.o \
	${OBJECTDIR}/Storage.o \
	${OBJECTDIR}/StorageSDDPiBAS.o \
	${OBJECTDIR}/StorageSDd.o \
	${OBJECTDIR}/TransientStorage.o \
	${OBJECTDIR}/TransientStorage2D.o \
	${OBJECTDIR}/TwoChoicePPWithTunableLocalityClient.o \
	${OBJECTDIR}/TwoChoicePPWithTunableLocalityServer.o \
	${OBJECTDIR}/TwoChoicePPWithTunableLocalityStorage.o \
	${OBJECTDIR}/TwoChoicePPwithStashClient.o \
	${OBJECTDIR}/TwoChoicePPwithStashServer.o \
	${OBJECTDIR}/TwoChoicePPwithStashStorage.o \
	${OBJECTDIR}/TwoChoiceWithOneChoiceClient.o \
	${OBJECTDIR}/TwoChoiceWithOneChoiceServer.o \
	${OBJECTDIR}/TwoChoiceWithOneChoiceStorage.o \
	${OBJECTDIR}/TwoChoiceWithTunableLocalityClient.o \
	${OBJECTDIR}/TwoChoiceWithTunableLocalityServer.o \
	${OBJECTDIR}/TwoChoiceWithTunableLocalityStorage.o \
	${OBJECTDIR}/Utilities.o \
	${OBJECTDIR}/logger.o \
	${OBJECTDIR}/main.o \
	${OBJECTDIR}/utils.o


# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=-mssse3 -msse2 -msse -march=native -maes -fprefetch-loop-arrays
CXXFLAGS=-mssse3 -msse2 -msse -march=native -maes -fprefetch-loop-arrays

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=-lcrypto -lssl -lstxxl_debug

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/dse-with-io-locality

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/dse-with-io-locality: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	g++ -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/dse-with-io-locality ${OBJECTFILES} ${LDLIBSOPTIONS} -lpthread -lcrypto -lssl

${OBJECTDIR}/AES.o: AES.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AES.o AES.cpp

${OBJECTDIR}/AVLTree.o: AVLTree.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AVLTree.o AVLTree.cpp

${OBJECTDIR}/Amortized3.o: Amortized3.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Amortized3.o Amortized3.cpp

${OBJECTDIR}/AmortizedBASClient.o: AmortizedBASClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedBASClient.o AmortizedBASClient.cpp

${OBJECTDIR}/AmortizedBASServer.o: AmortizedBASServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedBASServer.o AmortizedBASServer.cpp

${OBJECTDIR}/AmortizedNlogN.o: AmortizedNlogN.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedNlogN.o AmortizedNlogN.cpp

${OBJECTDIR}/AmortizedOneChoice.o: AmortizedOneChoice.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedOneChoice.o AmortizedOneChoice.cpp

${OBJECTDIR}/AmortizedPiBAS.o: AmortizedPiBAS.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedPiBAS.o AmortizedPiBAS.cpp

${OBJECTDIR}/AmortizedTwoChoice.o: AmortizedTwoChoice.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedTwoChoice.o AmortizedTwoChoice.cpp

${OBJECTDIR}/Bid.o: Bid.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Bid.o Bid.cpp

${OBJECTDIR}/DeAmortizedBASClient.o: DeAmortizedBASClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/DeAmortizedBASClient.o DeAmortizedBASClient.cpp

${OBJECTDIR}/DeAmortizedBASServer.o: DeAmortizedBASServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/DeAmortizedBASServer.o DeAmortizedBASServer.cpp

${OBJECTDIR}/DeAmortizedSDdBAS.o: DeAmortizedSDdBAS.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/DeAmortizedSDdBAS.o DeAmortizedSDdBAS.cpp

${OBJECTDIR}/DeAmortizedSDdGeneral.o: DeAmortizedSDdGeneral.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/DeAmortizedSDdGeneral.o DeAmortizedSDdGeneral.cpp

${OBJECTDIR}/DeAmortizedSDdNlogN.o: DeAmortizedSDdNlogN.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/DeAmortizedSDdNlogN.o DeAmortizedSDdNlogN.cpp

${OBJECTDIR}/DeAmortizedSDdPlaintext.o: DeAmortizedSDdPlaintext.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/DeAmortizedSDdPlaintext.o DeAmortizedSDdPlaintext.cpp

${OBJECTDIR}/NlogNClient.o: NlogNClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNClient.o NlogNClient.cpp

${OBJECTDIR}/NlogNSDdGeneralClient.o: NlogNSDdGeneralClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNSDdGeneralClient.o NlogNSDdGeneralClient.cpp

${OBJECTDIR}/NlogNServer.o: NlogNServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNServer.o NlogNServer.cpp

${OBJECTDIR}/NlogNStorage.o: NlogNStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNStorage.o NlogNStorage.cpp

${OBJECTDIR}/NlogNWithOptimalLocalityClient.o: NlogNWithOptimalLocalityClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNWithOptimalLocalityClient.o NlogNWithOptimalLocalityClient.cpp

${OBJECTDIR}/NlogNWithOptimalLocalityServer.o: NlogNWithOptimalLocalityServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNWithOptimalLocalityServer.o NlogNWithOptimalLocalityServer.cpp

${OBJECTDIR}/NlogNWithOptimalLocalityStorage.o: NlogNWithOptimalLocalityStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNWithOptimalLocalityStorage.o NlogNWithOptimalLocalityStorage.cpp

${OBJECTDIR}/NlogNWithTunableLocalityClient.o: NlogNWithTunableLocalityClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNWithTunableLocalityClient.o NlogNWithTunableLocalityClient.cpp

${OBJECTDIR}/NlogNWithTunableLocalityServer.o: NlogNWithTunableLocalityServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNWithTunableLocalityServer.o NlogNWithTunableLocalityServer.cpp

${OBJECTDIR}/NlogNWithTunableLocalityStorage.o: NlogNWithTunableLocalityStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNWithTunableLocalityStorage.o NlogNWithTunableLocalityStorage.cpp

${OBJECTDIR}/OMAP.o: OMAP.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OMAP.o OMAP.cpp

${OBJECTDIR}/ORAM.o: ORAM.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/ORAM.o ORAM.cpp

${OBJECTDIR}/OneChoiceClient.o: OneChoiceClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceClient.o OneChoiceClient.cpp

${OBJECTDIR}/OneChoiceSDdGeneralClient.o: OneChoiceSDdGeneralClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceSDdGeneralClient.o OneChoiceSDdGeneralClient.cpp

${OBJECTDIR}/OneChoiceSDdGeneralServer.o: OneChoiceSDdGeneralServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceSDdGeneralServer.o OneChoiceSDdGeneralServer.cpp

${OBJECTDIR}/OneChoiceSDdNoOMAPClient.o: OneChoiceSDdNoOMAPClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceSDdNoOMAPClient.o OneChoiceSDdNoOMAPClient.cpp

${OBJECTDIR}/OneChoiceSDdNoOMAPServer.o: OneChoiceSDdNoOMAPServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceSDdNoOMAPServer.o OneChoiceSDdNoOMAPServer.cpp

${OBJECTDIR}/OneChoiceSDdNoOMAPStorage.o: OneChoiceSDdNoOMAPStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceSDdNoOMAPStorage.o OneChoiceSDdNoOMAPStorage.cpp

${OBJECTDIR}/OneChoiceSDdOMAPClient.o: OneChoiceSDdOMAPClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceSDdOMAPClient.o OneChoiceSDdOMAPClient.cpp

${OBJECTDIR}/OneChoiceSDdOMAPServer.o: OneChoiceSDdOMAPServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceSDdOMAPServer.o OneChoiceSDdOMAPServer.cpp

${OBJECTDIR}/OneChoiceSDdOMAPStorage.o: OneChoiceSDdOMAPStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceSDdOMAPStorage.o OneChoiceSDdOMAPStorage.cpp

${OBJECTDIR}/OneChoiceServer.o: OneChoiceServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceServer.o OneChoiceServer.cpp

${OBJECTDIR}/OneChoiceStorage.o: OneChoiceStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceStorage.o OneChoiceStorage.cpp

${OBJECTDIR}/RAMStore.o: RAMStore.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/RAMStore.o RAMStore.cpp

${OBJECTDIR}/Server.o: Server.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Server.o Server.cpp

${OBJECTDIR}/Storage.o: Storage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Storage.o Storage.cpp

${OBJECTDIR}/StorageSDDPiBAS.o: StorageSDDPiBAS.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/StorageSDDPiBAS.o StorageSDDPiBAS.cpp

${OBJECTDIR}/StorageSDd.o: StorageSDd.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/StorageSDd.o StorageSDd.cpp

${OBJECTDIR}/TransientStorage.o: TransientStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TransientStorage.o TransientStorage.cpp

${OBJECTDIR}/TransientStorage2D.o: TransientStorage2D.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TransientStorage2D.o TransientStorage2D.cpp

${OBJECTDIR}/TwoChoicePPWithTunableLocalityClient.o: TwoChoicePPWithTunableLocalityClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoicePPWithTunableLocalityClient.o TwoChoicePPWithTunableLocalityClient.cpp

${OBJECTDIR}/TwoChoicePPWithTunableLocalityServer.o: TwoChoicePPWithTunableLocalityServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoicePPWithTunableLocalityServer.o TwoChoicePPWithTunableLocalityServer.cpp

${OBJECTDIR}/TwoChoicePPWithTunableLocalityStorage.o: TwoChoicePPWithTunableLocalityStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoicePPWithTunableLocalityStorage.o TwoChoicePPWithTunableLocalityStorage.cpp

${OBJECTDIR}/TwoChoicePPwithStashClient.o: TwoChoicePPwithStashClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoicePPwithStashClient.o TwoChoicePPwithStashClient.cpp

${OBJECTDIR}/TwoChoicePPwithStashServer.o: TwoChoicePPwithStashServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoicePPwithStashServer.o TwoChoicePPwithStashServer.cpp

${OBJECTDIR}/TwoChoicePPwithStashStorage.o: TwoChoicePPwithStashStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoicePPwithStashStorage.o TwoChoicePPwithStashStorage.cpp

${OBJECTDIR}/TwoChoiceWithOneChoiceClient.o: TwoChoiceWithOneChoiceClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithOneChoiceClient.o TwoChoiceWithOneChoiceClient.cpp

${OBJECTDIR}/TwoChoiceWithOneChoiceServer.o: TwoChoiceWithOneChoiceServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithOneChoiceServer.o TwoChoiceWithOneChoiceServer.cpp

${OBJECTDIR}/TwoChoiceWithOneChoiceStorage.o: TwoChoiceWithOneChoiceStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithOneChoiceStorage.o TwoChoiceWithOneChoiceStorage.cpp

${OBJECTDIR}/TwoChoiceWithTunableLocalityClient.o: TwoChoiceWithTunableLocalityClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithTunableLocalityClient.o TwoChoiceWithTunableLocalityClient.cpp

${OBJECTDIR}/TwoChoiceWithTunableLocalityServer.o: TwoChoiceWithTunableLocalityServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithTunableLocalityServer.o TwoChoiceWithTunableLocalityServer.cpp

${OBJECTDIR}/TwoChoiceWithTunableLocalityStorage.o: TwoChoiceWithTunableLocalityStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithTunableLocalityStorage.o TwoChoiceWithTunableLocalityStorage.cpp

${OBJECTDIR}/Utilities.o: Utilities.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Utilities.o Utilities.cpp

${OBJECTDIR}/logger.o: logger.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/logger.o logger.cpp

${OBJECTDIR}/main.o: main.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/main.o main.cpp

${OBJECTDIR}/utils.o: utils.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -I/usr/include/openssl -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/utils.o utils.cpp

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
