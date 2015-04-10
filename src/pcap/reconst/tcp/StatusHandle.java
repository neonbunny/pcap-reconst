package pcap.reconst.tcp;

/**
 * Class for communicating the status of packet parsing between the parser and a controlling thread.
 */
public class StatusHandle 
{
	/** Has the user requested that the parser stops */
	private boolean cancelled = false;
	/** Wrapper for the parser's cancel action, if applicable */
	private Cancellable cancellable = null;
	
	protected void setCancellable(Cancellable cancelleable)
	{
		this.cancellable = cancelleable;
	}
	
	/** True if the user requested that the parser should stop */
	public boolean isCancelled() 
	{
		return cancelled;
	}

	/**
	 * Flags that the parser should stop processing, and calls the parser's halt
	 * action if available. The parsers halt action will only be called once, regardless
	 * of how many times this method is called.
	 */
	public void cancel()
	{
		if (cancellable != null && !cancelled)
		{
			cancellable.cancel();
		}
		cancelled = true;
	}
	
	/**
	 * Interface which must be implemented by parsers that support cancelling.
	 * The implemented method(s) will be called when the user requests a cancellation.
	 */
	public static interface Cancellable
	{
		/**
		 * Method which halts the current parsing.
		 */
		void cancel();
	}
}
