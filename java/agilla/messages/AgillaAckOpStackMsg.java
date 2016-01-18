/**
 * This class is automatically generated by mig. DO NOT EDIT THIS FILE.
 * This class implements a Java interface to the 'AgillaAckOpStackMsg'
 * message type.
 */

package agilla.messages;

public class AgillaAckOpStackMsg extends net.tinyos.message.Message {

    /** The default size of this message type in bytes. */
    public static final int DEFAULT_MESSAGE_SIZE = 4;

    /** The Active Message type associated with this message. */
    public static final int AM_TYPE = 24;

    /** Create a new AgillaAckOpStackMsg of size 4. */
    public AgillaAckOpStackMsg() {
        super(DEFAULT_MESSAGE_SIZE);
        amTypeSet(AM_TYPE);
    }

    /** Create a new AgillaAckOpStackMsg of the given data_length. */
    public AgillaAckOpStackMsg(int data_length) {
        super(data_length);
        amTypeSet(AM_TYPE);
    }

    /**
     * Create a new AgillaAckOpStackMsg with the given data_length
     * and base offset.
     */
    public AgillaAckOpStackMsg(int data_length, int base_offset) {
        super(data_length, base_offset);
        amTypeSet(AM_TYPE);
    }

    /**
     * Create a new AgillaAckOpStackMsg using the given byte array
     * as backing store.
     */
    public AgillaAckOpStackMsg(byte[] data) {
        super(data);
        amTypeSet(AM_TYPE);
    }

    /**
     * Create a new AgillaAckOpStackMsg using the given byte array
     * as backing store, with the given base offset.
     */
    public AgillaAckOpStackMsg(byte[] data, int base_offset) {
        super(data, base_offset);
        amTypeSet(AM_TYPE);
    }

    /**
     * Create a new AgillaAckOpStackMsg using the given byte array
     * as backing store, with the given base offset and data length.
     */
    public AgillaAckOpStackMsg(byte[] data, int base_offset, int data_length) {
        super(data, base_offset, data_length);
        amTypeSet(AM_TYPE);
    }

    /**
     * Create a new AgillaAckOpStackMsg embedded in the given message
     * at the given base offset.
     */
    public AgillaAckOpStackMsg(net.tinyos.message.Message msg, int base_offset) {
        super(msg, base_offset, DEFAULT_MESSAGE_SIZE);
        amTypeSet(AM_TYPE);
    }

    /**
     * Create a new AgillaAckOpStackMsg embedded in the given message
     * at the given base offset and length.
     */
    public AgillaAckOpStackMsg(net.tinyos.message.Message msg, int base_offset, int data_length) {
        super(msg, base_offset, data_length);
        amTypeSet(AM_TYPE);
    }

    /**
    /* Return a String representation of this message. Includes the
     * message type name and the non-indexed field values.
     */
    public String toString() {
      String s = "Message <AgillaAckOpStackMsg> \n";
      try {
        s += "  [id.id=0x"+Long.toHexString(get_id_id())+"]\n";
      } catch (ArrayIndexOutOfBoundsException aioobe) { /* Skip field */ }
      try {
        s += "  [accept=0x"+Long.toHexString(get_accept())+"]\n";
      } catch (ArrayIndexOutOfBoundsException aioobe) { /* Skip field */ }
      try {
        s += "  [startAddr=0x"+Long.toHexString(get_startAddr())+"]\n";
      } catch (ArrayIndexOutOfBoundsException aioobe) { /* Skip field */ }
      return s;
    }

    // Message-type-specific access methods appear below.

    /////////////////////////////////////////////////////////
    // Accessor methods for field: id.id
    //   Field type: int, unsigned
    //   Offset (bits): 0
    //   Size (bits): 16
    /////////////////////////////////////////////////////////

    /**
     * Return whether the field 'id.id' is signed (false).
     */
    public static boolean isSigned_id_id() {
        return false;
    }

    /**
     * Return whether the field 'id.id' is an array (false).
     */
    public static boolean isArray_id_id() {
        return false;
    }

    /**
     * Return the offset (in bytes) of the field 'id.id'
     */
    public static int offset_id_id() {
        return (0 / 8);
    }

    /**
     * Return the offset (in bits) of the field 'id.id'
     */
    public static int offsetBits_id_id() {
        return 0;
    }

    /**
     * Return the value (as a int) of the field 'id.id'
     */
    public int get_id_id() {
        return (int)getUIntBEElement(offsetBits_id_id(), 16);
    }

    /**
     * Set the value of the field 'id.id'
     */
    public void set_id_id(int value) {
        setUIntBEElement(offsetBits_id_id(), 16, value);
    }

    /**
     * Return the size, in bytes, of the field 'id.id'
     */
    public static int size_id_id() {
        return (16 / 8);
    }

    /**
     * Return the size, in bits, of the field 'id.id'
     */
    public static int sizeBits_id_id() {
        return 16;
    }

    /////////////////////////////////////////////////////////
    // Accessor methods for field: accept
    //   Field type: short, unsigned
    //   Offset (bits): 16
    //   Size (bits): 8
    /////////////////////////////////////////////////////////

    /**
     * Return whether the field 'accept' is signed (false).
     */
    public static boolean isSigned_accept() {
        return false;
    }

    /**
     * Return whether the field 'accept' is an array (false).
     */
    public static boolean isArray_accept() {
        return false;
    }

    /**
     * Return the offset (in bytes) of the field 'accept'
     */
    public static int offset_accept() {
        return (16 / 8);
    }

    /**
     * Return the offset (in bits) of the field 'accept'
     */
    public static int offsetBits_accept() {
        return 16;
    }

    /**
     * Return the value (as a short) of the field 'accept'
     */
    public short get_accept() {
        return (short)getUIntBEElement(offsetBits_accept(), 8);
    }

    /**
     * Set the value of the field 'accept'
     */
    public void set_accept(short value) {
        setUIntBEElement(offsetBits_accept(), 8, value);
    }

    /**
     * Return the size, in bytes, of the field 'accept'
     */
    public static int size_accept() {
        return (8 / 8);
    }

    /**
     * Return the size, in bits, of the field 'accept'
     */
    public static int sizeBits_accept() {
        return 8;
    }

    /////////////////////////////////////////////////////////
    // Accessor methods for field: startAddr
    //   Field type: short, unsigned
    //   Offset (bits): 24
    //   Size (bits): 8
    /////////////////////////////////////////////////////////

    /**
     * Return whether the field 'startAddr' is signed (false).
     */
    public static boolean isSigned_startAddr() {
        return false;
    }

    /**
     * Return whether the field 'startAddr' is an array (false).
     */
    public static boolean isArray_startAddr() {
        return false;
    }

    /**
     * Return the offset (in bytes) of the field 'startAddr'
     */
    public static int offset_startAddr() {
        return (24 / 8);
    }

    /**
     * Return the offset (in bits) of the field 'startAddr'
     */
    public static int offsetBits_startAddr() {
        return 24;
    }

    /**
     * Return the value (as a short) of the field 'startAddr'
     */
    public short get_startAddr() {
        return (short)getUIntBEElement(offsetBits_startAddr(), 8);
    }

    /**
     * Set the value of the field 'startAddr'
     */
    public void set_startAddr(short value) {
        setUIntBEElement(offsetBits_startAddr(), 8, value);
    }

    /**
     * Return the size, in bytes, of the field 'startAddr'
     */
    public static int size_startAddr() {
        return (8 / 8);
    }

    /**
     * Return the size, in bits, of the field 'startAddr'
     */
    public static int sizeBits_startAddr() {
        return 8;
    }

}
