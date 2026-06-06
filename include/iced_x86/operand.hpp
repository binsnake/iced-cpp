// SPDX-License-Identifier: MIT
// Copyright (C) 2018-present iced project and contributors

#pragma once
#ifndef ICED_X86_OPERAND_HPP
#define ICED_X86_OPERAND_HPP

/// @file
/// @brief Ergonomic, indexable operand views over a decoded Instruction.
///
/// @details This header adds a Rust-flavored operand API on top of the flat
/// Instruction accessors (op_kind / op_register / immediate* / memory_*):
///
/// @code
///   auto op = instruction.op0();              // or instruction.op(0) / instruction.operands()[0]
///   if (op.type() == OperandType::REGISTER) { Register r = op.reg(); }
///   if (op.type() == OperandType::IMMEDIATE) {
///       if (op.imm().type() == ImmediateType::IMMEDIATE32) {
///           uint64_t u = op.imm().as_unsigned();
///           int64_t  s = op.imm().as_signed();
///       }
///   }
///   if (op.type() == OperandType::MEMORY) { uint64_t a = op.mem().absolute_address(); }
///
///   bool same = iced_x86::compare_operands(instruction.op0(), instruction.op1());
/// @endcode
///
/// Everything here is a non-owning view: an Operand is just a pointer to the
/// Instruction plus an operand index, so the Instruction must outlive it.

#include "instruction.hpp"
#include "memory_operand.hpp"
#include "op_kind.hpp"
#include "register.hpp"
#include "register_info.hpp"

#include <cstdint>

namespace iced_x86 {

	enum class OperandType : uint8_t; // defined below

	namespace detail {
		/// @brief Inline equivalent of Instruction::op_kind() (which is out-of-line in
		/// instruction.cpp). Reads the field directly so view code stays inlinable.
		/// Valid for index 0-4 (the only indices our API produces).
		[[nodiscard]] constexpr OpKind op_kind_fast(const Instruction& i, uint32_t index) noexcept {
			switch (index) {
			case 0:  return i.op0_kind();
			case 1:  return i.op1_kind();
			case 2:  return i.op2_kind();
			case 3:  return i.op3_kind();
			default: return OpKind::IMMEDIATE8; // op4 is always IMMEDIATE8
			}
		}
		/// @brief Inline equivalent of Instruction::op_register().
		[[nodiscard]] constexpr Register op_reg_fast(const Instruction& i, uint32_t index) noexcept {
			switch (index) {
			case 0:  return i.op0_register();
			case 1:  return i.op1_register();
			case 2:  return i.op2_register();
			case 3:  return i.op3_register();
			default: return Register::NONE;   // op4 register is always NONE
			}
		}
		/// @brief Classifies a raw OpKind into a high-level OperandType.
		[[nodiscard]] constexpr OperandType classify(OpKind kind) noexcept;

		/// @brief Effective value width of an immediate OpKind, in bits (the target
		/// width for sign-extended kinds, e.g. IMMEDIATE8TO32 -> 32).
		[[nodiscard]] constexpr uint32_t immediate_bits(OpKind kind) noexcept {
			switch (kind) {
			case OpKind::IMMEDIATE8:
			case OpKind::IMMEDIATE8_2ND:   return 8;
			case OpKind::IMMEDIATE16:
			case OpKind::IMMEDIATE8TO16:   return 16;
			case OpKind::IMMEDIATE32:
			case OpKind::IMMEDIATE8TO32:   return 32;
			case OpKind::IMMEDIATE64:
			case OpKind::IMMEDIATE8TO64:
			case OpKind::IMMEDIATE32TO64:  return 64;
			default:                       return 0;
			}
		}
	} // namespace detail

	/// @brief High-level classification of an operand.
	enum class OperandType : uint8_t {
		/// @brief Operand index is out of range (>= op_count()).
		NONE = 0,
		/// @brief A register operand. Use Operand::reg().
		REGISTER = 1,
		/// @brief An immediate constant. Use Operand::imm().
		IMMEDIATE = 2,
		/// @brief A memory operand. Use Operand::mem().
		MEMORY = 3,
		/// @brief A near branch target. Use Operand::near_branch_target().
		NEAR_BRANCH = 4,
		/// @brief A far branch target. Use Operand::far_branch_offset()/far_branch_selector().
		FAR_BRANCH = 5,
	};

	namespace detail {
		[[nodiscard]] constexpr OperandType classify(OpKind kind) noexcept {
			switch (kind) {
			case OpKind::REGISTER:
				return OperandType::REGISTER;
			case OpKind::NEAR_BRANCH16:
			case OpKind::NEAR_BRANCH32:
			case OpKind::NEAR_BRANCH64:
				return OperandType::NEAR_BRANCH;
			case OpKind::FAR_BRANCH16:
			case OpKind::FAR_BRANCH32:
				return OperandType::FAR_BRANCH;
			case OpKind::IMMEDIATE8:
			case OpKind::IMMEDIATE8_2ND:
			case OpKind::IMMEDIATE16:
			case OpKind::IMMEDIATE32:
			case OpKind::IMMEDIATE64:
			case OpKind::IMMEDIATE8TO16:
			case OpKind::IMMEDIATE8TO32:
			case OpKind::IMMEDIATE8TO64:
			case OpKind::IMMEDIATE32TO64:
				return OperandType::IMMEDIATE;
			default: // MEMORY_SEG_SI .. MEMORY
				return OperandType::MEMORY;
			}
		}
	} // namespace detail

	/// @brief Exact kind of an immediate operand (mirrors the immediate @ref OpKind values).
	enum class ImmediateType : uint8_t {
		IMMEDIATE8 = 0,        ///< 8-bit constant (@ref Instruction::immediate8)
		IMMEDIATE8_2ND = 1,    ///< 2nd 8-bit constant, ENTER/EXTRQ/INSERTQ (@ref Instruction::immediate8_2nd)
		IMMEDIATE16 = 2,       ///< 16-bit constant (@ref Instruction::immediate16)
		IMMEDIATE32 = 3,       ///< 32-bit constant (@ref Instruction::immediate32)
		IMMEDIATE64 = 4,       ///< 64-bit constant (@ref Instruction::immediate64)
		IMMEDIATE8TO16 = 5,    ///< 8-bit sign-extended to 16 bits (@ref Instruction::immediate8to16)
		IMMEDIATE8TO32 = 6,    ///< 8-bit sign-extended to 32 bits (@ref Instruction::immediate8to32)
		IMMEDIATE8TO64 = 7,    ///< 8-bit sign-extended to 64 bits (@ref Instruction::immediate8to64)
		IMMEDIATE32TO64 = 8,   ///< 32-bit sign-extended to 64 bits (@ref Instruction::immediate32to64)
	};

	/// @brief Non-owning view of an immediate operand.
	struct Immediate {
		const Instruction* instr_ = nullptr; ///< @private Owning instruction
		OpKind kind_ = OpKind::IMMEDIATE8;   ///< @private Raw operand kind

		constexpr Immediate() noexcept = default;
		constexpr Immediate(const Instruction* instr, OpKind kind) noexcept : instr_(instr), kind_(kind) {}

		/// @brief Gets the exact immediate type. Only valid when the operand is an immediate.
		[[nodiscard]] constexpr ImmediateType type() const noexcept {
			switch (kind_) {
			case OpKind::IMMEDIATE8_2ND:  return ImmediateType::IMMEDIATE8_2ND;
			case OpKind::IMMEDIATE16:     return ImmediateType::IMMEDIATE16;
			case OpKind::IMMEDIATE32:     return ImmediateType::IMMEDIATE32;
			case OpKind::IMMEDIATE64:     return ImmediateType::IMMEDIATE64;
			case OpKind::IMMEDIATE8TO16:  return ImmediateType::IMMEDIATE8TO16;
			case OpKind::IMMEDIATE8TO32:  return ImmediateType::IMMEDIATE8TO32;
			case OpKind::IMMEDIATE8TO64:  return ImmediateType::IMMEDIATE8TO64;
			case OpKind::IMMEDIATE32TO64: return ImmediateType::IMMEDIATE32TO64;
			default:                      return ImmediateType::IMMEDIATE8;
			}
		}

		/// @brief Gets the immediate sign-extended to 64 bits.
		[[nodiscard]] constexpr int64_t as_signed() const noexcept {
			switch (kind_) {
			case OpKind::IMMEDIATE8:       return static_cast<int64_t>(static_cast<int8_t>(instr_->immediate8()));
			case OpKind::IMMEDIATE8_2ND:   return static_cast<int64_t>(static_cast<int8_t>(instr_->immediate8_2nd()));
			case OpKind::IMMEDIATE16:      return static_cast<int64_t>(static_cast<int16_t>(instr_->immediate16()));
			case OpKind::IMMEDIATE32:      return static_cast<int64_t>(static_cast<int32_t>(instr_->immediate32()));
			case OpKind::IMMEDIATE64:      return static_cast<int64_t>(instr_->immediate64());
			case OpKind::IMMEDIATE8TO16:   return static_cast<int64_t>(instr_->immediate8to16());
			case OpKind::IMMEDIATE8TO32:   return static_cast<int64_t>(instr_->immediate8to32());
			case OpKind::IMMEDIATE8TO64:   return instr_->immediate8to64();
			case OpKind::IMMEDIATE32TO64:  return instr_->immediate32to64();
			default:                       return 0;
			}
		}

		/// @brief Gets the raw immediate bit pattern zero-extended to 64 bits (its natural width).
		[[nodiscard]] constexpr uint64_t as_unsigned() const noexcept {
			switch (kind_) {
			case OpKind::IMMEDIATE8:       return instr_->immediate8();
			case OpKind::IMMEDIATE8_2ND:   return instr_->immediate8_2nd();
			case OpKind::IMMEDIATE16:      return instr_->immediate16();
			case OpKind::IMMEDIATE32:      return instr_->immediate32();
			case OpKind::IMMEDIATE64:      return instr_->immediate64();
			case OpKind::IMMEDIATE8TO16:   return static_cast<uint16_t>(instr_->immediate8to16());
			case OpKind::IMMEDIATE8TO32:   return static_cast<uint32_t>(instr_->immediate8to32());
			case OpKind::IMMEDIATE8TO64:   return static_cast<uint64_t>(instr_->immediate8to64());
			case OpKind::IMMEDIATE32TO64:  return static_cast<uint64_t>(instr_->immediate32to64());
			default:                       return 0;
			}
		}

		/// @brief Alias for as_unsigned(). (`value`, since `signed`/`unsigned` are reserved words.)
		[[nodiscard]] constexpr uint64_t value() const noexcept { return as_unsigned(); }

		/// @brief Effective value width in bits (8/16/32/64).
		[[nodiscard]] constexpr uint32_t size_in_bits() const noexcept { return detail::immediate_bits(kind_); }
	};

	/// @brief Non-owning view of a memory operand.
	struct MemoryOperandView {
		const Instruction* instr_ = nullptr; ///< @private Owning instruction
		OpKind kind_ = OpKind::MEMORY;       ///< @private Raw operand kind

		constexpr MemoryOperandView() noexcept = default;
		constexpr MemoryOperandView(const Instruction* instr, OpKind kind) noexcept : instr_(instr), kind_(kind) {}

		/// @brief Base register or Register::NONE.
		[[nodiscard]] constexpr Register base() const noexcept { return instr_->memory_base(); }
		/// @brief Index register or Register::NONE.
		[[nodiscard]] constexpr Register index() const noexcept { return instr_->memory_index(); }
		/// @brief Index scale (1, 2, 4, or 8).
		[[nodiscard]] constexpr uint32_t scale() const noexcept { return instr_->memory_index_scale(); }
		/// @brief 64-bit displacement.
		[[nodiscard]] constexpr uint64_t displacement() const noexcept { return instr_->memory_displacement64(); }
		/// @brief Displacement size in bytes (0/1/2/4/8).
		[[nodiscard]] constexpr uint32_t displacement_size() const noexcept { return instr_->memory_displ_size(); }
		/// @brief Effective segment register used for the access.
		[[nodiscard]] Register segment() const noexcept { return instr_->memory_segment(); }
		/// @brief true if this is an explicit MEMORY operand (vs. a string/implied seg:[reg] form).
		[[nodiscard]] constexpr bool is_explicit() const noexcept { return kind_ == OpKind::MEMORY; }
		/// @brief true if RIP/EIP-relative.
		[[nodiscard]] constexpr bool is_ip_relative() const noexcept { return instr_->is_ip_rel_memory_operand(); }

		/// @brief Gets the statically-known absolute address this operand references.
		/// @details For RIP/EIP-relative operands this is the resolved target. For a
		/// displacement-only operand (no base/index) it is the displacement itself.
		/// When base/index registers are involved the full address is only known at
		/// run time, so the displacement component is returned as a best effort.
		[[nodiscard]] constexpr uint64_t absolute_address() const noexcept {
			if (instr_->is_ip_rel_memory_operand())
				return instr_->ip_rel_memory_address();
			return instr_->memory_displacement64();
		}

		/// @brief Gets the memory access size in bytes (0 if unknown).
		[[nodiscard]] size_t size_bytes() const noexcept { return instr_->memory_size(); }

		/// @brief Converts this decoded memory operand into an encoder @ref MemoryOperand,
		/// so it can be fed back into Instruction's with_*() factories without copying fields by hand.
		/// @details Only meaningful for an explicit MEMORY operand; string/implied forms have no base/index.
		[[nodiscard]] MemoryOperand to_memory_operand() const noexcept {
			return MemoryOperand(
				instr_->memory_base(),
				instr_->memory_index(),
				instr_->memory_index_scale(),
				static_cast<int64_t>(instr_->memory_displacement64()),
				instr_->memory_displ_size(),
				instr_->is_broadcast(),
				instr_->segment_prefix());
		}
	};

	/// @brief Non-owning, indexable view of a single instruction operand.
	struct Operand {
		const Instruction* instr_ = nullptr; ///< @private Owning instruction
		uint32_t index_ = 0;                 ///< @private Operand index (0-4)

		constexpr Operand() noexcept = default;
		constexpr Operand(const Instruction* instr, uint32_t index) noexcept : instr_(instr), index_(index) {}

		/// @brief Gets the operand index.
		[[nodiscard]] constexpr uint32_t index() const noexcept { return index_; }

		/// @brief Gets the raw @ref OpKind of this operand (inline, no bounds check).
		[[nodiscard]] constexpr OpKind kind() const noexcept { return detail::op_kind_fast(*instr_, index_); }

		/// @brief Checks if the operand index is within op_count().
		/// @details The only accessor here that costs an out-of-line op_count() lookup.
		[[nodiscard]] bool is_valid() const noexcept { return index_ < instr_->op_count(); }

		/// @brief Gets the high-level @ref OperandType classification.
		/// @details Returns NONE if the index is out of range. If you have already
		/// validated the index (e.g. iterating operands()), prefer type_of(kind()).
		[[nodiscard]] OperandType type() const noexcept {
			if (index_ >= instr_->op_count())
				return OperandType::NONE;
			return detail::classify(kind());
		}

		[[nodiscard]] bool is_register() const noexcept { return type() == OperandType::REGISTER; }
		[[nodiscard]] bool is_immediate() const noexcept { return type() == OperandType::IMMEDIATE; }
		[[nodiscard]] bool is_memory() const noexcept { return type() == OperandType::MEMORY; }
		[[nodiscard]] bool is_near_branch() const noexcept { return type() == OperandType::NEAR_BRANCH; }
		[[nodiscard]] bool is_far_branch() const noexcept { return type() == OperandType::FAR_BRANCH; }

		/// @brief Gets the register. Only valid when type() == OperandType::REGISTER.
		[[nodiscard]] constexpr Register reg() const noexcept { return detail::op_reg_fast(*instr_, index_); }

		/// @brief Gets the immediate view. Only valid when type() == OperandType::IMMEDIATE.
		[[nodiscard]] constexpr Immediate imm() const noexcept { return Immediate(instr_, kind()); }

		/// @brief Gets the memory view. Only valid when type() == OperandType::MEMORY.
		[[nodiscard]] constexpr MemoryOperandView mem() const noexcept { return MemoryOperandView(instr_, kind()); }

		/// @brief Gets the near branch target. Only valid when type() == OperandType::NEAR_BRANCH.
		[[nodiscard]] constexpr uint64_t near_branch_target() const noexcept {
			switch (kind()) {
			case OpKind::NEAR_BRANCH16: return instr_->near_branch16();
			case OpKind::NEAR_BRANCH32: return instr_->near_branch32();
			case OpKind::NEAR_BRANCH64: return instr_->near_branch64();
			default:                    return 0;
			}
		}

		/// @brief Gets the far branch offset. Only valid when type() == OperandType::FAR_BRANCH.
		[[nodiscard]] constexpr uint32_t far_branch_offset() const noexcept {
			return kind() == OpKind::FAR_BRANCH16 ? instr_->far_branch16() : instr_->far_branch32();
		}

		/// @brief Gets the far branch selector. Only valid when type() == OperandType::FAR_BRANCH.
		[[nodiscard]] constexpr uint16_t far_branch_selector() const noexcept { return instr_->far_branch_selector(); }

		/// @brief Gets the operand width in bits, or 0 if not applicable / out of range.
		/// @details Register: register width. Immediate: effective value width. Memory:
		/// access size. Near/far branch: target/offset width.
		[[nodiscard]] uint32_t size_in_bits() const noexcept {
			switch (type()) {
			case OperandType::REGISTER:
				return static_cast<uint32_t>(register_size(reg()) * 8);
			case OperandType::IMMEDIATE:
				return detail::immediate_bits(kind());
			case OperandType::MEMORY:
				return static_cast<uint32_t>(instr_->memory_size() * 8);
			case OperandType::NEAR_BRANCH:
				switch (kind()) {
				case OpKind::NEAR_BRANCH16: return 16;
				case OpKind::NEAR_BRANCH32: return 32;
				default:                    return 64;
				}
			case OperandType::FAR_BRANCH:
				return kind() == OpKind::FAR_BRANCH16 ? 16 : 32;
			default:
				return 0;
			}
		}
	};

	/// @brief Structural equality (see @ref compare_operands).
	[[nodiscard]] inline bool operator==(const Operand& a, const Operand& b) noexcept;
	[[nodiscard]] inline bool operator!=(const Operand& a, const Operand& b) noexcept { return !(a == b); }

	/// @brief Lightweight indexable proxy returned by Instruction::operands().
	/// @details Allows `instruction.operands()[i]`. Holds only an Instruction pointer.
	struct OperandList {
		const Instruction* instr_ = nullptr; ///< @private Owning instruction

		constexpr OperandList() noexcept = default;
		constexpr explicit OperandList(const Instruction* instr) noexcept : instr_(instr) {}

		/// @brief Number of operands (Instruction::op_count()).
		[[nodiscard]] uint32_t size() const noexcept { return instr_->op_count(); }

		/// @brief Gets operand @p index (0-4). No bounds checking beyond the raw accessors.
		[[nodiscard]] constexpr Operand operator[](uint32_t index) const noexcept { return Operand(instr_, index); }

		/// @brief Forward iterator over the used operands (0 .. op_count()-1).
		struct iterator {
			const Instruction* instr_ = nullptr;
			uint32_t index_ = 0;
			[[nodiscard]] constexpr Operand operator*() const noexcept { return Operand(instr_, index_); }
			constexpr iterator& operator++() noexcept { ++index_; return *this; }
			[[nodiscard]] constexpr bool operator==(const iterator& o) const noexcept { return index_ == o.index_; }
			[[nodiscard]] constexpr bool operator!=(const iterator& o) const noexcept { return index_ != o.index_; }
		};

		/// @brief Begin iterator. Enables `for (auto op : instruction.operands())`.
		[[nodiscard]] iterator begin() const noexcept { return iterator{ instr_, 0 }; }
		/// @brief End iterator (one past op_count()).
		[[nodiscard]] iterator end() const noexcept { return iterator{ instr_, instr_->op_count() }; }
	};

	/// @brief Structurally compares two operands.
	/// @return true if both operands are the same type and have identical contents
	/// (register, immediate type+bits, memory addressing, or branch target).
	[[nodiscard]] inline bool compare_operands(const Operand& a, const Operand& b) noexcept {
		const OperandType ta = a.type();
		if (ta != b.type())
			return false;
		switch (ta) {
		case OperandType::NONE:
			return true;
		case OperandType::REGISTER:
			return a.reg() == b.reg();
		case OperandType::IMMEDIATE:
			return a.imm().type() == b.imm().type() && a.imm().as_unsigned() == b.imm().as_unsigned();
		case OperandType::MEMORY: {
			if (a.kind() != b.kind())
				return false;
			const MemoryOperandView ma = a.mem();
			const MemoryOperandView mb = b.mem();
			if (ma.is_explicit()) {
				if (ma.base() != mb.base() || ma.index() != mb.index() ||
				    ma.scale() != mb.scale() || ma.displacement() != mb.displacement())
					return false;
			}
			return ma.segment() == mb.segment();
		}
		case OperandType::NEAR_BRANCH:
			return a.kind() == b.kind() && a.near_branch_target() == b.near_branch_target();
		case OperandType::FAR_BRANCH:
			return a.kind() == b.kind() &&
			       a.far_branch_offset() == b.far_branch_offset() &&
			       a.far_branch_selector() == b.far_branch_selector();
		}
		return false;
	}

	inline bool operator==(const Operand& a, const Operand& b) noexcept { return compare_operands(a, b); }

	// === Instruction operand accessors (declared in instruction.hpp) ===

	inline Operand Instruction::op(uint32_t index) const noexcept { return Operand(this, index); }
	inline Operand Instruction::op0() const noexcept { return Operand(this, 0); }
	inline Operand Instruction::op1() const noexcept { return Operand(this, 1); }
	inline Operand Instruction::op2() const noexcept { return Operand(this, 2); }
	inline Operand Instruction::op3() const noexcept { return Operand(this, 3); }
	inline Operand Instruction::op4() const noexcept { return Operand(this, 4); }
	inline OperandList Instruction::operands() const noexcept { return OperandList(this); }

} // namespace iced_x86

#endif // ICED_X86_OPERAND_HPP
