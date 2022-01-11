#include <vector>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <thread>
#include <iostream>

using namespace std;
class ThreadPool {
   public:
    size_t numTaskRemaining;
    ThreadPool(int cnt) : stop(false), numTaskRemaining(0) {
      // initialize the threadpool
      for (int i = 0; i < cnt; i++) {
        threads.push_back(std::thread([this] { doTask(); }));
      }
    }

    ~ThreadPool() {
      // first finish all remaining tasks
      waitAll();
      std::unique_lock<std::mutex> lck(mtx);
      this->stop = true;
      // notify all thread to finish
      this->cv.notify_all();
      lck.unlock();
      for (auto & th : threads) {
        if (th.joinable()) {
          th.join();
        }
      }
    }

    void addTask(std::function<void(void)> task) {
      std::unique_lock<std::mutex> lck(mtx); // new // need to lock to protect tasks queue
      this->tasks.push(task);
      this->numTaskRemaining++;
      // envoke a thread to do the task
      this->cv.notify_one();
    }

    // This function will notify the threadpool to run all task until the queue is empty;
    void waitAll() {
      std::unique_lock<std::mutex> lck(mtx);
      this->cv_finished.wait(lck, [this] { return this->numTaskRemaining == 0; });
    }

    void vectorsize(){
      cout << "threads vector size = " << threads.size() << endl;
    }

   private:
    std::vector<std::thread> threads;
    std::queue<std::function<void(void)> > tasks;
    // global mutex, use to protext the task queue
    std::mutex mtx;
    std::condition_variable cv;
    std::condition_variable cv_finished;
    bool stop;
    // size_t numTaskRemaining;

    void doTask() {
      while (true) {
        std::unique_lock<std::mutex> lck(this->mtx);
        // use a conditional variable to wait
        this->cv.wait(lck, [this] {
          // already in the critical section, so can access these variables safely
          return !this->tasks.empty() || this->stop;
        });
        if (this->stop) {
          return;
        }
        // fetch a task
        std::function<void(void)> task = std::move(this->tasks.front());
        this->tasks.pop();
        lck.unlock();
        // no need to lock while doing the task
        // std::cout << "thread id = " << std::this_thread::get_id() << std::endl;
        task();
        // lock again to update the remaing tasks variable
        lck.lock();
        this->numTaskRemaining--;
        // notify the waitAll()
        cv_finished.notify_one();
      }
    }

  };