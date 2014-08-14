//===-- MipsOptionRecord.h - Abstraction for storing information ----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// MipsOptionRecord - Abstraction for storing arbitrary information in
// ELF files. Arbitrary information (e.g. register usage) can be stored in Mips
// specific ELF sections like .Mips.options. Specific records should subclass
// MipsOptionRecord and provide an implementation to EmitMipsOptionRecord which
// basically just dumps the information into an ELF section. More information
// about .Mips.option can be found in the SysV ABI and the 64-bit ELF Object
// specification.
//
//===----------------------------------------------------------------------===//

#ifndef MIPSOPTIONRECORD_H
#define MIPSOPTIONRECORD_H

#include "MCTargetDesc/MipsMCTargetDesc.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCRegisterInfo.h"

using namespace llvm;

namespace llvm {
class MipsELFStreamer;
class MCSubtargetInfo;
}

class MipsOptionRecord {
public:
  virtual ~MipsOptionRecord(){};
  virtual void EmitMipsOptionRecord() = 0;
};

class MipsRegInfoRecord : public MipsOptionRecord {
public:
  MipsRegInfoRecord(MipsELFStreamer *S, MCContext &Context,
                    const MCSubtargetInfo &STI)
      : Streamer(S), Context(Context), STI(STI) {
    ri_gprmask = 0;
    ri_cprmask[0] = ri_cprmask[1] = ri_cprmask[2] = ri_cprmask[3] = 0;
    ri_gp_value = 0;

    const MCRegisterInfo *TRI = Context.getRegisterInfo();
    GPR32RegClass = &(TRI->getRegClass(Mips::GPR32RegClassID));
    GPR64RegClass = &(TRI->getRegClass(Mips::GPR64RegClassID));
    FGR32RegClass = &(TRI->getRegClass(Mips::FGR32RegClassID));
    FGR64RegClass = &(TRI->getRegClass(Mips::FGR64RegClassID));
    AFGR64RegClass = &(TRI->getRegClass(Mips::AFGR64RegClassID));
    MSA128BRegClass = &(TRI->getRegClass(Mips::MSA128BRegClassID));
    COP2RegClass = &(TRI->getRegClass(Mips::COP2RegClassID));
    COP3RegClass = &(TRI->getRegClass(Mips::COP3RegClassID));
  }
  ~MipsRegInfoRecord() {}

  void EmitMipsOptionRecord();
  void SetPhysRegUsed(unsigned Reg, const MCRegisterInfo *MCRegInfo);

private:
  MipsELFStreamer *Streamer;
  MCContext &Context;
  const MCSubtargetInfo &STI;
  const MCRegisterClass *GPR32RegClass;
  const MCRegisterClass *GPR64RegClass;
  const MCRegisterClass *FGR32RegClass;
  const MCRegisterClass *FGR64RegClass;
  const MCRegisterClass *AFGR64RegClass;
  const MCRegisterClass *MSA128BRegClass;
  const MCRegisterClass *COP2RegClass;
  const MCRegisterClass *COP3RegClass;
  uint32_t ri_gprmask;
  uint32_t ri_cprmask[4];
  int64_t ri_gp_value;
};
#endif