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
CND_CONF=Release
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
	${OBJECTDIR}/NlogNClient.o \
	${OBJECTDIR}/NlogNSDdGeneralClient.o \
	${OBJECTDIR}/NlogNServer.o \
	${OBJECTDIR}/NlogNStorage.o \
	${OBJECTDIR}/OMAP.o \
	${OBJECTDIR}/ORAM.o \
	${OBJECTDIR}/OneChoiceClient.o \
	${OBJECTDIR}/OneChoiceSDdGeneralClient.o \
	${OBJECTDIR}/OneChoiceSDdGeneralServer.o \
	${OBJECTDIR}/OneChoiceServer.o \
	${OBJECTDIR}/OneChoiceStorage.o \
	${OBJECTDIR}/RAMStore.o \
	${OBJECTDIR}/Server.o \
	${OBJECTDIR}/Storage.o \
	${OBJECTDIR}/StorageSDDPiBAS.o \
	${OBJECTDIR}/StorageSDd.o \
	${OBJECTDIR}/TransientStorage.o \
	${OBJECTDIR}/TransientStorage2D.o \
	${OBJECTDIR}/TwoChoiceWithOneChoiceClient.o \
	${OBJECTDIR}/TwoChoiceWithOneChoiceServer.o \
	${OBJECTDIR}/TwoChoiceWithOneChoiceStorage.o \
	${OBJECTDIR}/Utilities.o \
	${OBJECTDIR}/main.o


# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/io-dse

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/io-dse: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.cc} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/io-dse ${OBJECTFILES} ${LDLIBSOPTIONS}

${OBJECTDIR}/AES.o: AES.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AES.o AES.cpp

${OBJECTDIR}/AVLTree.o: AVLTree.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AVLTree.o AVLTree.cpp

${OBJECTDIR}/AmortizedBASClient.o: AmortizedBASClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedBASClient.o AmortizedBASClient.cpp

${OBJECTDIR}/AmortizedBASServer.o: AmortizedBASServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedBASServer.o AmortizedBASServer.cpp

${OBJECTDIR}/AmortizedNlogN.o: AmortizedNlogN.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedNlogN.o AmortizedNlogN.cpp

${OBJECTDIR}/AmortizedOneChoice.o: AmortizedOneChoice.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedOneChoice.o AmortizedOneChoice.cpp

${OBJECTDIR}/AmortizedPiBAS.o: AmortizedPiBAS.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedPiBAS.o AmortizedPiBAS.cpp

${OBJECTDIR}/AmortizedTwoChoice.o: AmortizedTwoChoice.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/AmortizedTwoChoice.o AmortizedTwoChoice.cpp

${OBJECTDIR}/Bid.o: Bid.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Bid.o Bid.cpp

${OBJECTDIR}/DeAmortizedBASClient.o: DeAmortizedBASClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/DeAmortizedBASClient.o DeAmortizedBASClient.cpp

${OBJECTDIR}/DeAmortizedBASServer.o: DeAmortizedBASServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/DeAmortizedBASServer.o DeAmortizedBASServer.cpp

${OBJECTDIR}/DeAmortizedSDdBAS.o: DeAmortizedSDdBAS.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/DeAmortizedSDdBAS.o DeAmortizedSDdBAS.cpp

${OBJECTDIR}/DeAmortizedSDdGeneral.o: DeAmortizedSDdGeneral.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/DeAmortizedSDdGeneral.o DeAmortizedSDdGeneral.cpp

${OBJECTDIR}/DeAmortizedSDdNlogN.o: DeAmortizedSDdNlogN.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/DeAmortizedSDdNlogN.o DeAmortizedSDdNlogN.cpp

${OBJECTDIR}/NlogNClient.o: NlogNClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNClient.o NlogNClient.cpp

${OBJECTDIR}/NlogNSDdGeneralClient.o: NlogNSDdGeneralClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNSDdGeneralClient.o NlogNSDdGeneralClient.cpp

${OBJECTDIR}/NlogNServer.o: NlogNServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNServer.o NlogNServer.cpp

${OBJECTDIR}/NlogNStorage.o: NlogNStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/NlogNStorage.o NlogNStorage.cpp

${OBJECTDIR}/OMAP.o: OMAP.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OMAP.o OMAP.cpp

${OBJECTDIR}/ORAM.o: ORAM.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/ORAM.o ORAM.cpp

${OBJECTDIR}/OneChoiceClient.o: OneChoiceClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceClient.o OneChoiceClient.cpp

${OBJECTDIR}/OneChoiceSDdGeneralClient.o: OneChoiceSDdGeneralClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceSDdGeneralClient.o OneChoiceSDdGeneralClient.cpp

${OBJECTDIR}/OneChoiceSDdGeneralServer.o: OneChoiceSDdGeneralServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceSDdGeneralServer.o OneChoiceSDdGeneralServer.cpp

${OBJECTDIR}/OneChoiceServer.o: OneChoiceServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceServer.o OneChoiceServer.cpp

${OBJECTDIR}/OneChoiceStorage.o: OneChoiceStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/OneChoiceStorage.o OneChoiceStorage.cpp

${OBJECTDIR}/RAMStore.o: RAMStore.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/RAMStore.o RAMStore.cpp

${OBJECTDIR}/Server.o: Server.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Server.o Server.cpp

${OBJECTDIR}/Storage.o: Storage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Storage.o Storage.cpp

${OBJECTDIR}/StorageSDDPiBAS.o: StorageSDDPiBAS.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/StorageSDDPiBAS.o StorageSDDPiBAS.cpp

${OBJECTDIR}/StorageSDd.o: StorageSDd.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/StorageSDd.o StorageSDd.cpp

${OBJECTDIR}/TransientStorage.o: TransientStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TransientStorage.o TransientStorage.cpp

${OBJECTDIR}/TransientStorage2D.o: TransientStorage2D.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TransientStorage2D.o TransientStorage2D.cpp

${OBJECTDIR}/TwoChoiceWithOneChoiceClient.o: TwoChoiceWithOneChoiceClient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithOneChoiceClient.o TwoChoiceWithOneChoiceClient.cpp

${OBJECTDIR}/TwoChoiceWithOneChoiceServer.o: TwoChoiceWithOneChoiceServer.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithOneChoiceServer.o TwoChoiceWithOneChoiceServer.cpp

${OBJECTDIR}/TwoChoiceWithOneChoiceStorage.o: TwoChoiceWithOneChoiceStorage.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/TwoChoiceWithOneChoiceStorage.o TwoChoiceWithOneChoiceStorage.cpp

${OBJECTDIR}/Utilities.o: Utilities.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/Utilities.o Utilities.cpp

${OBJECTDIR}/main.o: main.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -O2 -std=c++14 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/main.o main.cpp

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
