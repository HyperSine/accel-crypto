#pragma once
#include <utility>

namespace accel {

    namespace Internal {

        // Deducting
        template<size_t __FirstIndex,
                 size_t __TargetIndex,
                 typename __FirstType,
                 typename... __LeftTypes>
        struct ForwardByIndex {

            // require __FirstTypeIndex < __TargetIndex
            // otherwise, it is not a valid usage
            static_assert(__FirstIndex < __TargetIndex,
                          "ForwardByIndex failure! __FirstIndex must be less than __TargetIndex.");

            // require __TargetIndex - __FirstTypeIndex <= sizeof...(__LeftTypes)
            // otherwise, __TargetIndex must be out of range.
            static_assert(__TargetIndex - __FirstIndex <= sizeof...(__LeftTypes),
                          "ForwardByIndex failure! Out of range.");

            // when __FirstTypeIndex != __TargetIndex
            // keep on searching
            static inline decltype(auto) Impl(__FirstType&& FirstArg, __LeftTypes&&... LeftArgs) {
                return ForwardByIndex<__FirstIndex + 1,
                                      __TargetIndex,
                                      __LeftTypes...>::Impl(std::forward<__LeftTypes>(LeftArgs)...);
            }
        };

        // Resolve
        template<size_t __TargetIndex,
                 typename __FirstType,
                 typename... __LeftTypes>
        struct ForwardByIndex<__TargetIndex,
                              __TargetIndex,
                              __FirstType,
                              __LeftTypes...> {

            // when __FirstIndex == __TargetIndex
            // return the argument found
            static inline decltype(auto) Impl(__FirstType&& FirstArg, __LeftTypes&&... LeftArgs) {
                return std::forward<__FirstType>(FirstArg);
            }

        };

    }

    template<size_t __Index, typename... __Types>
    decltype(auto) ForwardByIndex(__Types&&... Args) {
        return Internal::ForwardByIndex<0, __Index, __Types...>::Impl(std::forward<__Types>(Args)...);
    }

    template<size_t... __Indexes, typename __FunctionType, typename... __Types>
    decltype(auto) ShuffleForward(__FunctionType&& F, __Types&&... Args) {
        return F(ForwardByIndex<__Indexes>(Args...)...);
    }
}

