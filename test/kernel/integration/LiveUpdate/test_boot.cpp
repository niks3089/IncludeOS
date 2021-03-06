#include <kernel/os.hpp>
#include <kernel/syscalls.hpp>
#include <liveupdate>
#include <timers>
#include <system_log>
using namespace liu;

static std::vector<uint64_t> timestamps;
static buffer_t bloberino;

//#define DRIFTING_BINARY
#ifdef DRIFTING_BINARY
static char* blob_location = nullptr;
#endif

static void boot_save(Storage& storage, const buffer_t* blob)
{
  timestamps.push_back(OS::nanos_since_boot());
  storage.add_vector(0, timestamps);
  assert(blob != nullptr);
  // store binary blob for later
#ifdef DRIFTING_BINARY
  blob_location = (char*) OS::liveupdate_storage_area() - 0x200000 - blob->size();
  std::copy(blob->begin(), blob->end(), blob_location);

  storage.add<char*>(2, blob_location);
  storage.add<size_t>(2, blob->size());
#else
  storage.add_buffer(2, *blob);
#endif
}
static void boot_resume_all(Restore& thing)
{
  timestamps = thing.as_vector<uint64_t>(); thing.go_next();
  // calculate time spent
  auto t1 = timestamps.back();
  auto t2 = OS::nanos_since_boot();
  // set final time
  timestamps.back() = t2 - t1;
  // retrieve binary blob
#ifdef DRIFTING_BINARY
  blob_location = thing.as_type<char*>(); thing.go_next();
  size_t len = thing.as_type<size_t> (); thing.go_next();

  bloberino = buffer_t{blob_location, blob_location + len};
#else
  bloberino = thing.as_buffer(); thing.go_next();
#endif
  thing.pop_marker();
}

LiveUpdate::storage_func begin_test_boot()
{
  if (LiveUpdate::resume("test", boot_resume_all))
  {
    // OS must be able to tell it was live updated each time
    assert(OS::is_live_updated());

    if (timestamps.size() >= 30)
    {
      // calculate median by sorting
      std::sort(timestamps.begin(), timestamps.end());
      auto median = timestamps[timestamps.size()/2];
      // show information
      printf("Median boot time over %lu samples: %.2f millis\n",
              timestamps.size(), median / 1000000.0);
      /*
      for (auto& stamp : timestamps) {
        printf("%lld\n", stamp);
      }
      */
      printf("Verifying that timers are started...\n");

      using namespace std::chrono;
      Timers::oneshot(5ms,[] (int) {
        printf("SUCCESS\n");
        SystemLog::print_to(OS::default_stdout);
      });
      return nullptr;
    }
    else {
      // immediately liveupdate
      LiveUpdate::exec(bloberino, "test", boot_save);
    }
  }
  // wait for update
  return boot_save;
}
