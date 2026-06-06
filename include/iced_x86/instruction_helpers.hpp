// SPDX-License-Identifier: MIT
// Copyright (C) 2018-present iced project and contributors

#pragma once
#ifndef ICED_X86_INSTRUCTION_HELPERS_HPP
#define ICED_X86_INSTRUCTION_HELPERS_HPP

/// @file
/// @brief Higher-level convenience helpers that depend on instruction info /
/// formatters. Kept out of operand.hpp so the lean operand views don't drag in
/// instruction_info.hpp or <string>.
///
/// @code
///   if (iced_x86::is_call(instr) || iced_x86::is_jmp(instr)) { ... }
///   std::string s = iced_x86::operand_to_string(formatter, instr.op0());
/// @endcode

#include "instruction.hpp"
#include "instruction_info.hpp" // InstructionExtensions::flow_control
#include "flow_control.hpp"
#include "operand.hpp"
#include "register_info.hpp"

#include <cstdint>
#include <string>

namespace iced_x86 {

	// === Control-flow predicates =============================================
	// Thin wrappers over InstructionExtensions::flow_control(). Each call computes
	// flow control from a table; cache flow_control(instr) yourself if you need
	// several checks in a hot loop.

	/// @brief Gets the control-flow classification of the instruction.
	[[nodiscard]] inline FlowControl flow_control(const Instruction& instr) noexcept {
		return InstructionExtensions::flow_control(instr);
	}

	/// @brief true for CALL NEAR/FAR and indirect calls.
	[[nodiscard]] inline bool is_call(const Instruction& instr) noexcept {
		const FlowControl fc = InstructionExtensions::flow_control(instr);
		return fc == FlowControl::CALL || fc == FlowControl::INDIRECT_CALL;
	}

	/// @brief true for RET NEAR/FAR, IRET, SYSRET, etc.
	[[nodiscard]] inline bool is_ret(const Instruction& instr) noexcept {
		return InstructionExtensions::flow_control(instr) == FlowControl::RETURN;
	}

	/// @brief true for conditional branches (Jcc, LOOP, JRCXZ, ...).
	[[nodiscard]] inline bool is_conditional_jmp(const Instruction& instr) noexcept {
		return InstructionExtensions::flow_control(instr) == FlowControl::CONDITIONAL_BRANCH;
	}

	/// @brief true for unconditional/indirect jumps (JMP NEAR/FAR, JMP reg/[mem]).
	[[nodiscard]] inline bool is_unconditional_jmp(const Instruction& instr) noexcept {
		const FlowControl fc = InstructionExtensions::flow_control(instr);
		return fc == FlowControl::UNCONDITIONAL_BRANCH || fc == FlowControl::INDIRECT_BRANCH;
	}

	/// @brief true for any jump (conditional, unconditional, or indirect). Excludes call/ret.
	[[nodiscard]] inline bool is_jmp(const Instruction& instr) noexcept {
		const FlowControl fc = InstructionExtensions::flow_control(instr);
		return fc == FlowControl::UNCONDITIONAL_BRANCH ||
		       fc == FlowControl::INDIRECT_BRANCH ||
		       fc == FlowControl::CONDITIONAL_BRANCH;
	}

	/// @brief true if the instruction may transfer control elsewhere (any call/jmp/ret/interrupt).
	[[nodiscard]] inline bool changes_control_flow(const Instruction& instr) noexcept {
		const FlowControl fc = InstructionExtensions::flow_control(instr);
		return fc != FlowControl::NEXT;
	}

	// === Operand → string ====================================================

	namespace detail {
		inline void append_hex(std::string& out, uint64_t value) {
			static const char* digits = "0123456789abcdef";
			out += "0x";
			bool started = false;
			for (int shift = 60; shift >= 0; shift -= 4) {
				const uint32_t nib = (value >> shift) & 0xF;
				if (nib != 0 || started || shift == 0) {
					out += digits[nib];
					started = true;
				}
			}
		}

		inline void append_signed_hex(std::string& out, int64_t value) {
			if (value < 0) { out += '-'; append_hex(out, static_cast<uint64_t>(-value)); }
			else append_hex(out, static_cast<uint64_t>(value));
		}
	} // namespace detail

	/// @brief Renders a single operand to a compact debug string.
	/// @tparam Formatter Any iced formatter exposing `format_register(Register)` (Intel/Masm/Nasm/Gas).
	/// @details Register names come from @p formatter so they match its style; immediates and
	/// memory are rendered as `0x..` / `[seg:base+index*scale+disp]`. Intended for logging/debug,
	/// not byte-exact reproduction of a formatter's full operand syntax.
	template <typename Formatter>
	[[nodiscard]] std::string operand_to_string(const Formatter& formatter, const Operand& op) {
		std::string out;
		switch (op.type()) {
		case OperandType::NONE:
			break;
		case OperandType::REGISTER:
			out += formatter.format_register(op.reg());
			break;
		case OperandType::IMMEDIATE:
			detail::append_signed_hex(out, op.imm().as_signed());
			break;
		case OperandType::MEMORY: {
			const MemoryOperandView m = op.mem();
			out += '[';
			bool wrote = false;
			if (const Register seg = m.segment(); seg != Register::NONE) {
				out += formatter.format_register(seg);
				out += ':';
			}
			if (m.base() != Register::NONE) { out += formatter.format_register(m.base()); wrote = true; }
			if (m.index() != Register::NONE) {
				if (wrote) out += '+';
				out += formatter.format_register(m.index());
				if (m.scale() > 1) { out += '*'; out += static_cast<char>('0' + static_cast<char>(m.scale())); }
				wrote = true;
			}
			const int64_t disp = static_cast<int64_t>(m.displacement());
			if (disp != 0 || !wrote) {
				if (wrote && disp >= 0) out += '+';
				detail::append_signed_hex(out, disp);
			}
			out += ']';
			break;
		}
		case OperandType::NEAR_BRANCH:
			detail::append_hex(out, op.near_branch_target());
			break;
		case OperandType::FAR_BRANCH:
			detail::append_hex(out, op.far_branch_selector());
			out += ':';
			detail::append_hex(out, op.far_branch_offset());
			break;
		}
		return out;
	}

} // namespace iced_x86

#endif // ICED_X86_INSTRUCTION_HELPERS_HPP
