#ifndef FACTORY_MANAGER_H
#define FACTORY_MANAGER_H

#include "IHash.h"
#include "SHA3-512.h"
#include "general.h"
#include "sha256.h"
#include <functional>
#include <map>
#include <memory>

class HashFactory {
   public:
    static HashFactory &getInstance();
    CK_RV create(const SHAAlgorithm &type,
                 std::unique_ptr<IHash> &hashPtr) const;

   private:
    std::map<SHAAlgorithm, std::function<std::unique_ptr<IHash>()>> factories;
    HashFactory();  // Private constructor for singleton pattern.
};

#endif  // FACTORY_MANAGER_H