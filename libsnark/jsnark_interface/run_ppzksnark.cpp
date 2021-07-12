/*
 * run_ppzksnark.cpp
 *
 *      Author: Ahmed Kosba
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_se_ppzksnark/examples/run_r1cs_se_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_se_ppzksnark_pp.hpp>

enum PROOF_SYSTEM
{
	R1CS_PPZKSNARK = 0,
	R1CS_GG_PPZKSNARK,
	R1CS_SE_PPZKSNARK
};

int main(int argc, char **argv)
{

	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

	int inputStartIndex = 0;
	PROOF_SYSTEM proofSystem = R1CS_PPZKSNARK;
	if (argc == 4){
		if (strcmp(argv[1], "R1CS_PPZKSNARK") == 0){
			proofSystem = R1CS_PPZKSNARK;
			cout << "Using ppzsknark in " << argv[1] << endl;
		}
		else if (strcmp(argv[1], "R1CS_GG_PPZKSNARK") == 0 || strcmp(argv[1], "gg") == 0){
			proofSystem = R1CS_GG_PPZKSNARK;
			cout << "Using ppzsknark in " << argv[1] << endl;
		}
		else if (strcmp(argv[1], "R1CS_SE_PPZKSNARK") == 0 || strcmp(argv[1], "se") == 0){
			proofSystem = R1CS_SE_PPZKSNARK;
			cout << "Using ppzsknark in " << argv[1] << endl;
		}
		else{
			cout << "Invalid Argument - Terminating.." << endl;
			return -1;
		}
		inputStartIndex = 1;	
	} 	

	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(
			*pb);
	const r1cs_variable_assignment<FieldT> full_assignment =
			get_variable_assignment_from_gadgetlib2(*pb);
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

	// extract primary and auxiliary input
	const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
			full_assignment.begin() + cs.num_inputs());
	const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());


	// only print the circuit output values if both flags MONTGOMERY and BINARY outputs are off (see CMakeLists file)
	// In the default case, these flags should be ON for faster performance.

#if !defined(MONTGOMERY_OUTPUT) && !defined(OUTPUT_BINARY)
	cout << endl << "Printing output assignment in readable format:: " << endl;
	std::vector<Wire> outputList = reader.getOutputWireIds();
	int start = reader.getNumInputs();
	int end = reader.getNumInputs() +reader.getNumOutputs();	
	for (int i = start ; i < end; i++) {
		cout << "[output]" << " Value of Wire # " << outputList[i-reader.getNumInputs()] << " :: ";
		cout << primary_input[i];
		cout << endl;
	}
	cout << endl;
#endif

	//assert(cs.is_valid());

	// removed cs.is_valid() check due to a suspected (off by 1) issue in a newly added check in their method.
        // A follow-up will be added.
	if(!cs.is_satisfied(primary_input, auxiliary_input)){
		cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
		return -1;
	}


	r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);
	
	const bool test_serialization = false;
	bool successBit = false;
	if(argc == 3) {
		successBit = libsnark::run_r1cs_ppzksnark<libff::default_ec_pp>(example, test_serialization);

	} else {
		// The following code makes use of the observation that 
		// libsnark::default_r1cs_gg_ppzksnark_pp is the same as libff::default_ec_pp (see r1cs_gg_ppzksnark_pp.hpp)
		// libsnark::default_r1cs_se_ppzksnark_pp is the same as libff::default_ec_pp
		// libsnark::default_r1cs_ppzksnark_pp is the same as libff::default_ec_pp

		// otherwise, the following code won't work properly, as GadgetLib2 is hardcoded to use libff::default_ec_pp.
		switch (proofSystem)
		{
		case R1CS_PPZKSNARK:
			successBit = libsnark::run_r1cs_ppzksnark<libff::default_ec_pp>(example, test_serialization);
			break;
		case R1CS_GG_PPZKSNARK:
			successBit = libsnark::run_r1cs_gg_ppzksnark<libff::default_ec_pp>(example, test_serialization);
			break;
		case R1CS_SE_PPZKSNARK:
			successBit = libsnark::run_r1cs_se_ppzksnark<libff::default_ec_pp>(example, test_serialization);
			break;
		}
	}

	if(!successBit){
		cout << "Problem occurred while running the ppzksnark algorithms .. " << endl;
		return -1;
	}	
	return 0;
}

