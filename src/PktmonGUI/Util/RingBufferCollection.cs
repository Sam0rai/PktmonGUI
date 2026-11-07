using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace PktmonGUI.Util
{
    /// <summary>
    /// ObservableCollection with a capacity cap for the live packet grid. Items arrive in
    /// batches; the oldest are discarded in chunks (a tenth of the cap at a time) so the
    /// grid resets rarely instead of shifting on every packet.
    /// </summary>
    public sealed class RingBufferCollection<T> : ObservableCollection<T>
    {
        // WPF's CollectionView rejects multi-item Add notifications, so large batches
        // are announced as a Reset instead of hundreds of single-item events.
        private const int ResetThreshold = 400;

        public RingBufferCollection(int capacity) { Capacity = capacity; }

        public int Capacity { get; set; }

        /// <summary>Total items ever discarded because of the cap.</summary>
        public long Discarded { get; private set; }

        public void AddRange(IList<T> batch)
        {
            if (batch.Count == 0) return;
            CheckReentrancy();

            bool reset = batch.Count > ResetThreshold;
            int overflow = Items.Count + batch.Count - Capacity;
            if (overflow > 0)
            {
                int chunk = System.Math.Max(overflow, System.Math.Max(1, Capacity / 10));
                chunk = System.Math.Min(chunk, Items.Count);
                ((List<T>)Items).RemoveRange(0, chunk);
                Discarded += chunk;
                // A batch that alone exceeds the cap keeps only its newest items.
                if (batch.Count > Capacity)
                {
                    Discarded += batch.Count - Capacity;
                    batch = new List<T>(batch).GetRange(batch.Count - Capacity, Capacity);
                }
                reset = true;
            }

            if (reset)
            {
                ((List<T>)Items).AddRange(batch);
                OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
                OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
                OnPropertyChanged(new PropertyChangedEventArgs(nameof(Discarded)));
                OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
            }
            else
            {
                foreach (var item in batch) Add(item);
            }
        }

        public new void Clear()
        {
            Discarded = 0;
            base.Clear();
            OnPropertyChanged(new PropertyChangedEventArgs(nameof(Discarded)));
        }
    }
}
