#pragma once
#include <utility>

namespace accel {

    // deduct
    template<size_t __FirstTypeIndex,
             size_t __TargetIndex,
             typename __FirstType,
             typename... __LeftTypes>
    struct _ForwardByIndex_IMPL {

        // require __FirstTypeIndex < __TargetIndex
        // otherwise, it is not a valid usage
        static_assert(__FirstTypeIndex < __TargetIndex,
                      "_ForwardByIndex_S failure! __FirstTypeIndex must be less than __TargetIndex");

        // require __TargetIndex - __FirstTypeIndex <= sizeof...(__LeftTypes)
        // otherwise, __TargetIndex must be out of range.
        static_assert(__TargetIndex - __FirstTypeIndex <= sizeof...(__LeftTypes),
                      "_ForwardByIndex_S failure! Out of range.");

        // when __FirstTypeIndex != __TargetIndex
        // keep on searching
        static decltype(auto) impl(__FirstType&& FirstArg, __LeftTypes&&... LeftArgs) {
            return _ForwardByIndex_IMPL<__FirstTypeIndex + 1,
                                        __TargetIndex,
                                        __LeftTypes...>::impl(std::forward<__LeftTypes>(LeftArgs)...);
        }
    };

    // resolve
    template<size_t __TargetIndex,
             typename __FirstType,
             typename... __LeftTypes>
    struct _ForwardByIndex_IMPL<__TargetIndex,
                                __TargetIndex,
                                __FirstType,
                                __LeftTypes...> {

        // when __FirstTypeIndex == __TargetIndex
        // return the argument found
        static decltype(auto) impl(__FirstType&& FirstArg, __LeftTypes&&... LeftArgs) {
            return std::forward<__FirstType>(FirstArg);
        }

    };

    template<size_t __Index, typename... __Types>
    decltype(auto) ForwardByIndex(__Types&&... Args) {
        return _ForwardByIndex_IMPL<0, __Index, __Types...>::impl(std::forward<__Types>(Args)...);
    }

    template<size_t... __Indexes, typename __FunctionType, typename... __Types>
    decltype(auto) ShuffleForward(__FunctionType& F, __Types&&... Args) {
        return F(ForwardByIndex<__Indexes>(Args...)...);
    }
}

