#include "Agilla.h"
#include "TupleSpace.h"
#include "Wids.h"
#include "printf.h"

module IntrusionDetectionM {
	uses {
		interface Boot;
		interface AlarmGeneration;
		interface IntrusionDetection;
		interface TupleSpaceI as TS;
		interface TupleUtilI;
	}
} implementation {

	AgillaVariable *score = NULL;
	AgillaVariable *threat = NULL;

	AgillaTuple *t;

	wids_attack_t pAttack = NO_ATTACK;
	uint8_t attScore = 0;
	
	int16_t pos = 0;

	event void Boot.booted(){
		AgillaVariable *field = malloc(sizeof(AgillaVariable));
		t = malloc(sizeof(AgillaTuple));
		t->flags = AGILLA_TUPLE_SYSTEM; // set the tuple as system tuple
		
		// The first field identifies the tuple
		field->vtype = AGILLA_TYPE_STRING;
		field->string.string = AGILLA_TUPLE_STRING_WIDS;
		pos = call TupleUtilI.addField(t, pos, field);

		// The second one is the total score of the system
		score = malloc(sizeof(AgillaVariable));
		score->vtype = AGILLA_TYPE_VALUE;
		score->value.value = attScore;
		pos = call TupleUtilI.addField(t, pos, score);
 
		// The third field contains the attack with max score
		threat = malloc(sizeof(AgillaVariable));
		threat->vtype = AGILLA_TYPE_VALUE;
		threat->value.value = pAttack;
		pos = call TupleUtilI.addField(t, pos, threat);

		if(call TS.out(t) == SUCCESS)
			// correctly booted
			return;
		else
			//TODO: manage error;
			return;
	}

	event void AlarmGeneration.updated(){
		pAttack = call AlarmGeneration.maxScoreAttack();
		attScore = call AlarmGeneration.getSystemScore();

		score->value.value = attScore;
		threat->value.value = pAttack;

		call TS.out(t); // The tuple should be removed by the agent once read

		printf("Notified attack.\nSystem score %d with higher risk attack %s\n",
			call AlarmGeneration.getSystemScore(), printfAttack(call AlarmGeneration.maxScoreAttack()));

		printfflush();
	}

	event error_t TS.newTuple(AgillaTuple* tuple){ return SUCCESS; }
	
	event error_t TS.byteShift(uint16_t from, uint16_t amount){ return SUCCESS; }

}