#pragma once
#include "Config.hpp"
#include <utility>

namespace accel {

    namespace Internal {

        //
        // Deducting
        //
        template<size_t __CurrentIndex, size_t __TargetIndex, typename __CurrentType, typename... __LeftTypes>
        struct ForwardByIndex {
            //
            // Require __CurrentIndex < __TargetIndex
            // Otherwise, it is not a correct usage
            //
            static_assert(__CurrentIndex < __TargetIndex,
                          "ForwardByIndex failure! __FirstIndex must be less than __TargetIndex.");

            //
            // Require __TargetIndex - __CurrentIndex <= sizeof...(__LeftTypes)
            // Otherwise, __TargetIndex must be out of range.
            //
            static_assert(__TargetIndex - __CurrentIndex <= sizeof...(__LeftTypes),
                          "ForwardByIndex failure! Out of range.");

            //
            // When __CurrentIndex != __TargetIndex, keep on searching
            //
            ACCEL_NODISCARD
            static constexpr decltype(auto) Impl(__CurrentType&& FirstArg, __LeftTypes&&... LeftArgs) ACCEL_NOEXCEPT {
                return ForwardByIndex<__CurrentIndex + 1, __TargetIndex, __LeftTypes...>::Impl(std::forward<__LeftTypes>(LeftArgs)...);
            }
        };

        //
        // Resolve
        //
        template<size_t __TargetIndex, typename __CurrentType, typename... __LeftTypes>
        struct ForwardByIndex<__TargetIndex, __TargetIndex, __CurrentType, __LeftTypes...> {
            //
            // When __FirstIndex == __TargetIndex, return the argument found
            //
            ACCEL_NODISCARD
            static constexpr decltype(auto) Impl(__CurrentType&& FirstArg, __LeftTypes&&... LeftArgs) ACCEL_NOEXCEPT {
                return std::forward<__CurrentType>(FirstArg);
            }
        };

    }

    //
    // Forward arguments by index
    // e.g.
    //      `ForwardByIndex<2>(a, b, c, d)` will forward argument `c`
    //      `ForwardByIndex<3>(a, b, c, d)` will forward argument `d`
    //
    template<size_t __Index, typename... __Types>
    ACCEL_NODISCARD
    constexpr decltype(auto) ForwardByIndex(__Types&&... Args) ACCEL_NOEXCEPT {
        return Internal::ForwardByIndex<0, __Index, __Types...>::Impl(std::forward<__Types>(Args)...);
    }

    //
    // Calling `CallableObject` with shuffled arguments
    // e.g.
    //      `ShuffleForward<3, 2, 1, 1>(callable_obj, a, b, c, d)` is equivalent to `callable_obj(d, c, b, b)`
    //
    template<size_t... __Indexes, typename __CallableType, typename... __Types>
    constexpr decltype(auto) ShuffleForward(__CallableType&& CallableObject, __Types&&... Args) ACCEL_NOEXCEPT {
        return CallableObject(ForwardByIndex<__Indexes>(Args...)...);
    }
}

