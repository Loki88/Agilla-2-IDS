


configuration IntrusionDetectionC {
	
} implementation {

	components WIDSC, TupleSpaceProxy, TupleUtilC;
	components IntrusionDetectionM;

	IntrusionDetectionM.Boot -> WIDSC;
	IntrusionDetectionM.AlarmGeneration -> WIDSC;
	IntrusionDetectionM.TS -> TupleSpaceProxy.TupleSpaceI;
	IntrusionDetectionM.TupleUtilI -> TupleUtilC;
	
}