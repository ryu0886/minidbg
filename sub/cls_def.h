#pragma once

class CAutoLock
{
public:
    CAutoLock(void* lock);
    ~CAutoLock();
private:
    void* m_lock;
};